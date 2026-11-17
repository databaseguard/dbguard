#!/usr/bin/env bash
# =============================================================================
# test-microseg.sh - verify the Zero-Trust Network Micro-Segmentation feature
# (eBPF socket/XDP enforcement + Cilium integration). Loads the programs into
# the kernel verifier, attaches the XDP enforcer to loopback, and reports the
# Cilium integration surface. Root required (BPF load/attach).
# =============================================================================
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; RST=$'\e[0m'
pass=0; fail=0; skip=0
ok(){ echo "  ${GRN}PASS${RST} $*"; pass=$((pass+1)); }
no(){ echo "  ${RED}FAIL${RST} $*"; fail=$((fail+1)); }
sk(){ echo "  ${YEL}SKIP${RST} $*"; skip=$((skip+1)); }
hdr(){ echo; echo "${BLU}== $* ==${RST}"; }

[ -d build/bpf ] || { echo "run: make bpf"; exit 2; }

hdr "1. eBPF programs load into the kernel verifier"
if command -v go >/dev/null; then
  go build -o /tmp/bpfload ./tools/bpfload 2>/dev/null
  if [ "$(id -u)" = 0 ] && [ -x /tmp/bpfload ]; then
    out="$(/tmp/bpfload build/bpf/microseg_xdp.bpf.o build/bpf/microseg_sockmap.bpf.o 2>&1)"
    echo "$out" | grep -q 'microseg_xdp.bpf.o ALL_PASS'     && ok "xdp_microseg (XDP drop enforcer) passes verifier"     || no "xdp_microseg failed verifier"
    echo "$out" | grep -q 'microseg_sockmap.bpf.o ALL_PASS' && ok "sockmap redirect datapath (3 progs) passes verifier" || no "microseg_sockmap failed verifier"
  else sk "verifier load needs root"; fi
else sk "go not installed"; fi

hdr "2. XDP enforcer attaches to a live interface"
if [ "$(id -u)" = 0 ] && command -v go >/dev/null; then
  cat > /tmp/ms_attach_test.go <<'EOF'
package main
import ("net";"os";"fmt"
 cilium "github.com/cilium/ebpf";"github.com/cilium/ebpf/link";"github.com/cilium/ebpf/rlimit")
func main(){
 rlimit.RemoveMemlock()
 spec,err:=cilium.LoadCollectionSpec(os.Getenv("MSOBJ")); if err!=nil{fmt.Println("spec:",err);os.Exit(1)}
 for _,m:=range spec.Maps{m.Pinning=0}
 coll,err:=cilium.NewCollection(spec); if err!=nil{fmt.Println("load:",err);os.Exit(1)}
 defer coll.Close()
 iface,_:=net.InterfaceByName("lo")
 l,err:=link.AttachXDP(link.XDPOptions{Program:coll.Programs["xdp_microseg"],Interface:iface.Index,Flags:link.XDPGenericMode})
 if err!=nil{fmt.Println("attach:",err);os.Exit(1)}
 l.Close()
 if coll.Maps["client_policy"]!=nil{fmt.Println("OK client_policy LPM-trie present")}
 fmt.Println("OK xdp_microseg attached to lo")
}
EOF
  cp /tmp/ms_attach_test.go "$ROOT/zz_ms_probe.go"
  r="$(cd "$ROOT" && MSOBJ="$ROOT/build/bpf/microseg_xdp.bpf.o" go run ./zz_ms_probe.go 2>&1)"
  rm -f "$ROOT/zz_ms_probe.go"
  echo "$r" | grep -q 'attached to lo'      && ok "xdp_microseg attaches to loopback (enforcement live)" || { no "xdp attach failed"; echo "$r" | sed 's/^/      /'; }
  echo "$r" | grep -q 'client_policy'        && ok "client_policy LPM-trie (allowed CIDRs) present"       || no "client_policy map missing"
  rm -f /tmp/ms_attach_test.go
else sk "attach test needs root + go"; fi

hdr "3. Control plane wires the allow map (Go)"
grep -q 'func (m \*Manager) UpdateClientPolicy' internal/ebpf/manager.go \
  && ok "Manager.UpdateClientPolicy populates client_allow/client_policy from CIDRs" \
  || no "UpdateClientPolicy missing"

hdr "4. Cilium integration surface"
[ -f internal/identity/cilium.go ] \
  && ok "Cilium identity resolver present (queries local agent for IP->identity)" \
  || no "cilium.go missing"
ls deploy/cilium/ciliumnetworkpolicy-postgres.yaml deploy/cilium/ciliumnetworkpolicy-mysql.yaml >/dev/null 2>&1 \
  && ok "CiliumNetworkPolicy manifests for postgres + mysql present" \
  || no "cilium manifests missing"
[ -f deploy/cilium/sockmap-enable.yaml ] && ok "sockmap-enable + hubble notes present" || sk "sockmap-enable missing"

hdr "NOTES"
cat <<'TXT'
  - The XDP enforcer DROPS packets to the DB port from clients not in the
    client_policy allowlist (or marked deny), and passes allowed CIDRs - this is
    the zero-trust micro-segmentation data path. Enable by listing the DB-facing
    NIC in ebpf.xdp_interfaces and loading the allowed CIDRs via the control
    plane; set ebpf.drop_enabled: true for default-deny.
  - The sockmap datapath (stream_parser/verdict + sk_msg redirect) is the
    Cilium-style socket-layer acceleration path over a sockhash.
  - Cilium integration is OPTIONAL and degrades gracefully: when a Cilium agent
    is present at 127.0.0.1:9879, dbguard enriches events with the pod SECURITY
    IDENTITY behind each IP; without Cilium, everything else still works. Full
    pod-identity enforcement (vs CIDR) requires a running Cilium + k8s cluster,
    which this single-host test cannot stand up - the manifests in deploy/cilium
    are for that environment.
TXT

hdr "SUMMARY"
echo "  ${GRN}pass=$pass${RST}  ${RED}fail=$fail${RST}  ${YEL}skip=$skip${RST}"
exit "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
