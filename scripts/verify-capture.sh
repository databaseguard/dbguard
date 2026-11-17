#!/usr/bin/env bash
# =============================================================================
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
[ "$(id -u)" = 0 ] || { echo "run with sudo (eBPF load needs root)"; exit 2; }
command -v gcc >/dev/null || { echo "need gcc"; exit 2; }
[ -f build/bpf/audit.bpf.o ] || { echo "run 'make bpf' first"; exit 2; }

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cat > "$TMP/fakepg.c" <<'EOF'
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
__attribute__((noinline)) void exec_simple_query(const char *q){ volatile int n=(int)strlen(q); (void)n; }
int main(int argc,char**argv){
  const char* p[]={
    "SELECT id,email FROM customers WHERE id=42",
    "SELECT * FROM customers WHERE name='' OR 1=1 --",
    "SELECT a FROM t UNION SELECT credit_card,ssn FROM customers",
    "INSERT INTO log(card) VALUES('4111111111111111')",
    "SELECT * FROM users WHERE ssn='123-45-6789'"};
  int r=argc>1?atoi(argv[1]):30;
  for(int k=0;k<r;k++){ for(unsigned i=0;i<5;i++){ exec_simple_query(p[i]); usleep(50000);} }
  return 0;
}
EOF
gcc -O0 -g -o "$TMP/fakepg" "$TMP/fakepg.c" || exit 2
echo "stand-in symbol: $(nm "$TMP/fakepg" | grep exec_simple_query || echo MISSING)"

# Reuse the Go runtime harness compiled on the fly (keeps this script self-contained).
cat > "$TMP/main.go" <<'EOF'
package main
import ("fmt";"os";"os/exec";"time";"log/slog";"io"
 cilium "github.com/cilium/ebpf";"github.com/cilium/ebpf/link";"github.com/cilium/ebpf/ringbuf";"github.com/cilium/ebpf/rlimit"
 dbg "github.com/databaseguard/dbguard/internal/ebpf";"github.com/databaseguard/dbguard/internal/pii";"github.com/databaseguard/dbguard/internal/sqli";"github.com/databaseguard/dbguard/internal/config")
func main(){
 obj,fake:=os.Args[1],os.Args[2]
 rlimit.RemoveMemlock()
 spec,err:=cilium.LoadCollectionSpec(obj); if err!=nil{panic(err)}
 for _,m:=range spec.Maps{m.Pinning=0}
 for _,ps:=range spec.Programs{ if ps.Type==cilium.UnspecifiedProgram{ps.Type=cilium.Kprobe} }
 coll,err:=cilium.NewCollection(spec); if err!=nil{fmt.Println("load (expected on strict kernels w/ pii_prescan):",err);os.Exit(3)}
 defer coll.Close()
 ex,_:=link.OpenExecutable(fake)
 l,err:=ex.Uprobe("exec_simple_query",coll.Programs["uprobe_pg_simple"],nil); if err!=nil{panic(err)}; defer l.Close()
 rd,_:=ringbuf.NewReader(coll.Maps["events"]); defer rd.Close()
 cmd:=exec.Command(fake,"25"); cmd.Start(); defer cmd.Wait()
 coll.Maps["target_pids"].Put(uint32(cmd.Process.Pid),uint8(1))
 log:=slog.New(slog.NewTextHandler(io.Discard,nil))
 sq,_:=sqli.New(config.SQLiConfig{Sensitivity:"medium"},log); pd,_:=pii.New(config.PIIConfig{},log)
 var nq,ns,np int; seen:=map[string]bool{}
 rd.SetDeadline(time.Now().Add(6*time.Second))
 for{ rec,err:=rd.Read(); if err!=nil{break}
  ev,err:=dbg.DecodeEvent(rec.RawSample); if err!=nil||ev.SQL==""{continue}
  if !seen[ev.SQL]{ seen[ev.SQL]=true; nq++
   if sc,_:=sq.Analyze(ev.SQL); sc>=0.72{ ns++; fmt.Printf("  SQLi [%.2f] %s\n",sc,ev.SQL) }
   if fs:=pd.InspectText(ev.SQL); len(fs)>0{ np++; fmt.Printf("  PII  [%d]    %s\n",len(fs),ev.SQL) } } }
 fmt.Printf("\ncaptured=%d  sqli_hits=%d  pii_hits=%d\n",nq,ns,np)
 if nq==0||ns==0||np==0{ os.Exit(1) }
 fmt.Println("RESULT: capture -> detection pipeline VERIFIED")
}
EOF
echo "building verifier harness…"
go run "$TMP/main.go" build/bpf/audit.bpf.o "$TMP/fakepg"
rc=$?
if [ $rc -eq 3 ]; then
  echo
  echo "NOTE: your kernel's verifier rejected audit.bpf.o's in-kernel PII pre-scan"
  echo "when loaded as a full collection (kernel-version dependent). The capture"
  echo "logic is unchanged; disable it with config_map.pii_prescan=0 or test with"
  echo "a prescan-free build. On kernels that accept it (e.g. 6.8) this runs clean."
fi
exit $rc
