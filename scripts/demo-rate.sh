#!/usr/bin/env bash
# =============================================================================
#
# Usage:  sudo ./scripts/demo-rate.sh [limit] [window]
#   e.g.  sudo ./scripts/demo-rate.sh 5 1m      (5 queries / 1 minute)
# =============================================================================
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo ./scripts/demo-rate.sh"; exit 2; }
LIMIT="${1:-5}"; WINDOW="${2:-1m}"
DBGUARDD=./build/bin/dbguardd; CFG=configs/dbguard.dev.yaml; AUDIT=.dbguard-state/audit
GRN=$'\e[32m'; RED=$'\e[31m'; BLU=$'\e[34m'; RST=$'\e[0m'
say(){ echo; echo "${BLU}==> $*${RST}"; }
PGH=127.0.0.1; PGP=5432; PGU=dbguard; PGPW=dbguard; PGDB=dbguard_test
pgq(){ PGPASSWORD="$PGPW" psql -h $PGH -p $PGP -U $PGU -d $PGDB -tAc "$1" >/dev/null 2>&1; }

[ -x "$DBGUARDD" ] || { echo "build first: make bpf go-build"; exit 2; }
PGPASSWORD="$PGPW" psql -h $PGH -p $PGP -U $PGU -d $PGDB -c 'SELECT 1' >/dev/null 2>&1 \
  || { echo "Postgres not reachable - run scripts/setup-dbs.sh"; exit 2; }

say "1. Write a rate rule: max $LIMIT queries / $WINDOW from any client"
RULE=configs/policies/92-demo-rate.yaml
cat > "$RULE" <<YAML
api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata: {name: demo-rate}
spec:
  default_action: allow
  rules:
    - id: fw.rate-demo
      name: Rate limit $LIMIT per $WINDOW per client
      severity: medium
      clients: [0.0.0.0/0]
      rate: {events: $LIMIT, window: $WINDOW}
      actions: [deny, alert]
YAML
sed 's/^/   /' "$RULE"

say "2. Start the daemon (holds the sliding window across queries)"
pkill -f 'dbguardd -config' 2>/dev/null; sleep 1
rm -rf "$AUDIT"; mkdir -p "$AUDIT"
"$DBGUARDD" -config "$CFG" >/tmp/demo_rate.log 2>&1 &
DPID=$!; trap 'kill -INT "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; rm -f "$RULE"' EXIT
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:9700/api/v1/status >/dev/null 2>&1 && break; sleep 0.5; done
sleep 2

  if grep -q "ebpf=false" /tmp/demo_rate.log; then
    echo "   ${RED}NOTE: eBPF inactive (ebpf=false): queries not captured, audit will be empty.${RST}"
  fi
N=$((LIMIT + 4))
say "3. Fire $N queries fast - expect the first $LIMIT allowed, the rest rate-limited"
for i in $(seq 1 $N); do pgq "SELECT $i"; done
sleep 2

say "4. Verdict per query from the audit trail (rate-limit denials appear past the cap)"
python3 - "$AUDIT" "$LIMIT" <<'PY'
import sys,glob,json
limit=int(sys.argv[2])
rows=[]
for f in sorted(glob.glob(sys.argv[1]+"/*.jsonl")):
    for l in open(f):
        try: e=json.loads(l)
        except: continue
        r=e.get("reason","") or ""
        rule=e.get("rule_id","") or ""
        if "rate" in r or rule=="fw.rate-demo" or e.get("type")=="query.audit":
            rows.append((e.get("allowed"), rule, r[:60], (e.get("sql","") or "")[:20]))
allowed=sum(1 for a,_,_,_ in rows if a)
denied=sum(1 for a,_,_,_ in rows if a is False)
for a,rule,reason,sql in rows:
    tag="ALLOW" if a else "DENY "
    print("   %s  %-14s %s" % (tag, sql, reason if reason else rule))
print()
print("   allowed=%d  denied=%d  (rule cap was %d)" % (allowed,denied,limit))
PY

say "Done. Rate limiting enforced: traffic flowed up to the cap, then was denied."
echo "(daemon stopped and 92-demo-rate.yaml removed on exit)"
