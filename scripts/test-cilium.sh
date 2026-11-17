#!/usr/bin/env bash
# test-cilium.sh - prove the Cilium identity-binding feature on a single host,
# without a Kubernetes cluster.
#
#   ./scripts/test-cilium.sh
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$REPO_ROOT"
PGUSER_=dbguard PGPASS_=dbguard PGDB_=dbguard_test
IDENTITY_ID="${IDENTITY_ID:-99001}"
GRN=$'\e[32m'; RED=$'\e[31m'; YEL=$'\e[33m'; RST=$'\e[0m'
pass=0; fail=0
ok(){ echo "  ${GRN}PASS${RST} $*"; pass=$((pass+1)); }
no(){ echo "  ${RED}FAIL${RST} $*"; fail=$((fail+1)); }

command -v python3 >/dev/null || { echo "need python3 for the stub agent"; exit 2; }
[ -x build/bin/dbguardd ] || { echo "build first: make bpf go-build"; exit 2; }

cleanup(){ [ -n "${STUB_PID:-}" ] && kill "$STUB_PID" 2>/dev/null; [ -n "${DAEMON_PID:-}" ] && kill "$DAEMON_PID" 2>/dev/null; }
trap cleanup EXIT

echo "== 1. stub Cilium agent on :9879 (identity id=${IDENTITY_ID}) =="
STUB=/tmp/dbg_cilium_stub.py
cat > "$STUB" <<PY
import http.server, urllib.parse, json, sys
ID = "${IDENTITY_ID}"
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        q = urllib.parse.urlparse(self.path)
        ip = urllib.parse.parse_qs(q.query).get('ip',[''])[0]
        body = json.dumps({"security_identity":{"id":ID,"labels":["k8s:app=api-server"]}}).encode()
        self.send_response(200); self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*a): pass
http.server.HTTPServer(("127.0.0.1",9879),H).serve_forever()
PY
python3 -I "$STUB" & STUB_PID=$!
sleep 1
curl -fsS "http://127.0.0.1:9879/v1/identity?ip=127.0.0.1" >/dev/null 2>&1 \
  && ok "stub agent answering /v1/identity" || { no "stub agent not reachable"; exit 1; }

echo "== 2. dbguard with identity.cilium_enabled =="
# stop any service/instance so we own the ports
sudo systemctl stop dbguard 2>/dev/null || true
pkill -9 -f dbguardd 2>/dev/null || true; sleep 1
CFG=/tmp/dbg-dev-cilium.yaml
sed 's/cilium_enabled: false/cilium_enabled: true/' configs/dbguard.dev.yaml > "$CFG"
rm -rf .dbguard-state
sudo ./build/bin/dbguardd --config "$CFG" >/tmp/dbg-cilium.log 2>&1 & DAEMON_PID=$!
sleep 5
grep -q "cilium enrichment enabled" /tmp/dbg-cilium.log \
  && ok "cilium enrichment enabled at startup" || no "cilium enrichment not enabled (check log)"

echo "== 3. fire a denied query; event must carry the Cilium identity =="
PGPASSWORD="$PGPASS_" psql "host=127.0.0.1 port=6432 dbname=${PGDB_} user=${PGUSER_} sslmode=disable" \
  -c "SELECT id FROM customers UNION SELECT credit_card FROM customers;" >/dev/null 2>&1 || true
sleep 2
got="$(curl -fsS 'http://127.0.0.1:9700/api/v1/events?limit=10' 2>/dev/null | grep -o "\"cilium_identity\":\"${IDENTITY_ID}\"" | head -1)"
if [ -n "$got" ]; then
  ok "event carries cilium_identity=${IDENTITY_ID} (L3 identity bound to the L7 statement)"
else
  no "cilium_identity not found on the event"
  echo "    (recent events:)"; curl -fsS 'http://127.0.0.1:9700/api/v1/events?limit=3' 2>/dev/null | head -c 600; echo
fi

echo; echo "== SUMMARY =="; echo "  ${GRN}pass=$pass${RST}  ${RED}fail=$fail${RST}"
[ "$fail" -eq 0 ] && echo "  ${GRN}Cilium identity binding works${RST}" || echo "  ${RED}failures${RST}"
exit "$fail"
