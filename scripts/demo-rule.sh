#!/usr/bin/env bash
# =============================================================================
#
# Usage:  sudo ./scripts/demo-rule.sh
# Needs:  root (eBPF), built binaries, Postgres reachable as dbguard/dbguard.
# =============================================================================
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo ./scripts/demo-rule.sh"; exit 2; }
CLI=./build/bin/dbguard-cli; DBGUARDD=./build/bin/dbguardd
CFG=configs/dbguard.dev.yaml; AUDIT=.dbguard-state/audit
GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; RST=$'\e[0m'
say(){ echo; echo "${BLU}==> $*${RST}"; }
PGH=127.0.0.1; PGP=5432; PGU=dbguard; PGPW=dbguard; PGDB=dbguard_test
pgq(){ PGPASSWORD="$PGPW" psql -h $PGH -p $PGP -U $PGU -d $PGDB -tAc "$1" 2>/dev/null; }

[ -x "$DBGUARDD" ] || { echo "build first: make bpf go-build"; exit 2; }
pgq 'SELECT 1' >/dev/null || { echo "Postgres not reachable as $PGU@$PGDB - run scripts/setup-dbs.sh"; exit 2; }

say "1. Seed dummy data into a 'secrets' table"
pgq "DROP TABLE IF EXISTS secrets;
     CREATE TABLE secrets(id int, label text, api_key text);
     INSERT INTO secrets VALUES (1,'prod-db','sk-PROD-9f3c21'),(2,'stripe','sk-live-abc123');" >/dev/null
echo "   rows in secrets: $(pgq 'SELECT count(*) FROM secrets')"

say "2. Query the data directly - it returns rows (this is the DB working normally)"
echo "   $ psql -c 'SELECT id,label,api_key FROM secrets'"
PGPASSWORD="$PGPW" psql -h $PGH -p $PGP -U $PGU -d $PGDB -c "SELECT id,label,api_key FROM secrets" 2>/dev/null | sed 's/^/     /'

say "3. dry-run the firewall BEFORE adding a rule - the query is ALLOWED"
"$CLI" dry-run -c "$CFG" -e postgres -u bob "SELECT id,label,api_key FROM secrets" 2>/dev/null \
  | grep -E 'decision|rules' | sed 's/^/     /'

say "4. Add a firewall rule that blocks the secrets table"
RULE=configs/policies/91-demo-secrets.yaml
cat > "$RULE" <<YAML
api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata: {name: demo-secrets}
spec:
  default_action: allow
  rules:
    - id: fw.block-secrets
      name: Block any access to the secrets table
      severity: critical
      tables: [secrets]
      actions: [deny, alert]
YAML
echo "   wrote $RULE:"; sed 's/^/     /' "$RULE"
"$CLI" validate-policy -d configs/policies >/dev/null 2>&1 && echo "   ${GRN}policy validates${RST}"

say "5. dry-run AFTER adding the rule - the SAME query is now DENIED"
"$CLI" dry-run -c "$CFG" -e postgres -u bob "SELECT id,label,api_key FROM secrets" 2>/dev/null \
  | grep -E 'decision|rules|reason' | sed 's/^/     /'

say "6. Prove it live: start the daemon, run the query, read the audit verdict"
pkill -f 'dbguardd -config' 2>/dev/null; sleep 1
rm -rf "$AUDIT"; mkdir -p "$AUDIT"
"$DBGUARDD" -config "$CFG" >/tmp/demo_rule.log 2>&1 &
DPID=$!; trap 'kill -INT "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null; rm -f "$RULE"' EXIT
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:9700/api/v1/status >/dev/null 2>&1 && break; sleep 0.5; done
sleep 2
pgq "SELECT id,label,api_key FROM secrets" >/dev/null
sleep 2
echo "   audit records mentioning the secrets query:"
python3 - "$AUDIT" <<'PY' | sed 's/^/     /'
import sys,glob,json
for f in glob.glob(sys.argv[1]+"/*.jsonl"):
    for l in open(f):
        try: e=json.loads(l)
        except: continue
        if "secrets" in e.get("sql",""):
            print("type=%s allowed=%s rule=%s findings=%s"%(
                e.get("type"), e.get("allowed"), e.get("rule_id"),
                [x.get("kind") for x in e.get("findings",[])]))
PY

say "Done. The rule you wrote blocked a real query. Cleaning up (rule + table)."
pgq "DROP TABLE IF EXISTS secrets" >/dev/null
echo "${YEL}(the daemon is stopped and 91-demo-secrets.yaml removed on exit)${RST}"
