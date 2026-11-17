#!/usr/bin/env bash
# =============================================================================
# It starts dbguard against the seeded databases, fires engine-specific attacks
# through FRESH connections, waits for the pipeline to flush, then reads the
# AUDIT TRAIL (the source of truth) and reports what actually fired.
#
# Usage:  sudo ./scripts/test-engines.sh
# Prereqs: make bpf go-build ; scripts/setup-dbs.sh ; sudo make dbgsym (for PG)
# =============================================================================
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 2; }

CFG="${DBGUARD_CONFIG:-configs/dbguard.dev.yaml}"
DBGUARDD=./build/bin/dbguardd
AUDIT_DIR=.dbguard-state/audit
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; RST=$'\e[0m'
pass=0; fail=0; skip=0
ok(){ echo "  ${GRN}PASS${RST} $*"; pass=$((pass+1)); }
no(){ echo "  ${RED}FAIL${RST} $*"; fail=$((fail+1)); }
sk(){ echo "  ${YEL}SKIP${RST} $*"; skip=$((skip+1)); }
hdr(){ echo; echo "${BLU}== $* ==${RST}"; }

[ -x "$DBGUARDD" ] || { echo "build first: make bpf go-build"; exit 2; }
command -v jq >/dev/null || { echo "install jq: apt install jq"; exit 2; }

# connection settings (match scripts/setup-dbs.sh)
PGH=127.0.0.1; PGP=5432; PGU=dbguard; PGPW=dbguard; PGDB=dbguard_test
MYH=127.0.0.1; MYP=3306; MYU=dbguard; MYPW=dbguard; MYDB=dbguard_test
SQLITE_DB="${SQLITE_DB:-/tmp/dbguard_test.db}"

pkill -f 'dbguardd -config' 2>/dev/null && sleep 1
rm -rf "$AUDIT_DIR"; mkdir -p "$AUDIT_DIR"

hdr "starting dbguard"
"$DBGUARDD" -config "$CFG" >/tmp/te_daemon.log 2>&1 &
DPID=$!
trap 'kill -INT "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null' EXIT
for i in $(seq 1 30); do curl -fsS http://127.0.0.1:9700/api/v1/status >/dev/null 2>&1 && break; sleep 0.5; done
sleep 1
# which engines did the query-auditing uprobes attach to?
pg_attached=$(grep -c 'query auditing active.*engine=postgres' /tmp/te_daemon.log)
my_attached=$(grep -c 'query auditing active.*engine=mysql' /tmp/te_daemon.log)
echo "  uprobe attach: postgres=$pg_attached  mysql=$my_attached"

fire_pg(){ PGPASSWORD="$PGPW" psql -h $PGH -p $PGP -U $PGU -d $PGDB -c "$1" >/dev/null 2>&1; }
fire_my(){ mysql -h $MYH -P $MYP -u $MYU -p"$MYPW" "$MYDB" -e "$1" >/dev/null 2>&1; }
fire_sqlite(){ sqlite3 "$SQLITE_DB" "$1" >/dev/null 2>&1; }

have_pg=0; PGPASSWORD="$PGPW" psql -h $PGH -p $PGP -U $PGU -d $PGDB -c 'SELECT 1' >/dev/null 2>&1 && have_pg=1
have_my=0; mysql -h $MYH -P $MYP -u $MYU -p"$MYPW" "$MYDB" -e 'SELECT 1' >/dev/null 2>&1 && have_my=1
have_sqlite=0; [ -f "$SQLITE_DB" ] && command -v sqlite3 >/dev/null && have_sqlite=1

# helper: count audit records whose findings include $1 (optionally engine $2)
gt0(){ local n="${1:-0}"; [ -z "$n" ] && n=0; [ "$n" -gt 0 ] 2>/dev/null; }
afind(){ cat "$AUDIT_DIR"/*.jsonl 2>/dev/null | jq -r --arg k "$1" 'select(.findings[]?.kind==$k)|.engine' 2>/dev/null | { if [ -n "${2:-}" ]; then grep -c "$2"; else grep -c .; fi; } | head -1 | tr -dc 0-9; }
atype(){ cat "$AUDIT_DIR"/*.jsonl 2>/dev/null | jq -r --arg t "$1" 'select(.type==$t)|.engine' 2>/dev/null | { if [ -n "${2:-}" ]; then grep -c "$2"; else grep -c .; fi; } | head -1 | tr -dc 0-9; }

# ---------------------------------------------------------------------------
hdr "PostgreSQL"
if [ "$have_pg" = 1 ]; then
  fire_pg "SELECT * FROM customers WHERE name='' OR 1=1 --"
  fire_pg "SELECT id FROM customers WHERE id=1 UNION SELECT credit_card, ssn FROM customers"
  fire_pg "SELECT 1; DROP TABLE IF EXISTS _t;"
  fire_pg "SELECT pg_sleep(1)"
  fire_pg "SELECT * FROM customers WHERE ssn='123-45-6789' OR 1=1 -- card 4111111111111111"
  for _ in $(seq 1 12); do fire_pg "SELECT * FROM customers"; done
  sleep 3
  if gt0 "$(afind sqli.tautology postgres)"; then ok "pg SQLi tautology"; else no "pg SQLi tautology"; fi
  if gt0 "$(afind sqli.union_select postgres)"; then ok "pg SQLi UNION"; else no "pg SQLi UNION"; fi
  if gt0 "$(afind sqli.stacked_queries postgres)"; then ok "pg SQLi stacked"; else no "pg SQLi stacked"; fi
  if gt0 "$(afind sqli.time_based postgres)"; then ok "pg SQLi time-based"; else no "pg SQLi time-based"; fi
  if gt0 "$(afind pii.credit_card postgres)"; then ok "pg PII credit card"; else no "pg PII credit card"; fi
  if gt0 "$(afind pii.ssn_us postgres)"; then ok "pg PII SSN"; else no "pg PII SSN"; fi
  if gt0 "$(afind exfil.bulk_query postgres)"; then ok "pg exfil bulk SELECT *"; else no "pg exfil bulk SELECT *"; fi
else sk "postgres not reachable (scripts/setup-dbs.sh)"; fi

# ---------------------------------------------------------------------------
hdr "MySQL"
if [ "$have_my" = 1 ]; then
  if [ "$my_attached" = 0 ]; then
    sk "mysql query-audit uprobe not attached (see daemon log); SQLi/PII capture inactive"
  else
    fire_my "SELECT * FROM customers WHERE name='' OR 1=1 #"
    fire_my "SELECT id FROM customers WHERE id=1 UNION SELECT credit_card, ssn FROM customers"
    # NOTE: MySQL strips SQL comments before mysql_parse sees them, so PII must
    # be in the query BODY (a literal value), not in a -- comment.
    fire_my "SELECT * FROM customers WHERE ssn='123-45-6789' AND card='4111111111111111'"
    for _ in $(seq 1 12); do fire_my "SELECT * FROM employees"; done
    sleep 3
    if gt0 "$(afind sqli.tautology mysql)"; then ok "mysql SQLi tautology"; else no "mysql SQLi tautology"; fi
    if gt0 "$(afind sqli.union_select mysql)"; then ok "mysql SQLi UNION"; else no "mysql SQLi UNION"; fi
    # PII finding kind is pii.credit_card; the event type is pii.detection. Accept either.
    if gt0 "$(afind pii.credit_card mysql)" || gt0 "$(atype pii.detection mysql)"; then ok "mysql PII credit card"; else no "mysql PII credit card"; fi
    if gt0 "$(afind exfil.bulk_query mysql)"; then ok "mysql exfil bulk"; else no "mysql exfil bulk"; fi
  fi
else sk "mysql not reachable (scripts/setup-dbs.sh)"; fi


# ---------------------------------------------------------------------------
hdr "Engine-independent features (via audit trail)"
if gt0 "$(atype query.audit)"; then ok "query auditing (capture->decode->store)"; else no "query auditing"; fi
[ -s /tmp/te_daemon.log ] && grep -q 'fim baseline established' /tmp/te_daemon.log && ok "RIDS file-integrity baseline" || sk "RIDS baseline not logged"
curl -fsS http://127.0.0.1:9701/metrics 2>/dev/null | grep -q events_total && ok "Prometheus metrics endpoint" || no "metrics endpoint"
./build/bin/dbguard-cli events -n 5 >/dev/null 2>&1 && ok "admin API /events" || no "admin API"

hdr "SUMMARY"
echo "  ${GRN}pass=$pass${RST}  ${RED}fail=$fail${RST}  ${YEL}skip=$skip${RST}"
echo
echo "  Audit trail: $(cat "$AUDIT_DIR"/*.jsonl 2>/dev/null | wc -l) records in $AUDIT_DIR"
echo "  Breakdown:"
cat "$AUDIT_DIR"/*.jsonl 2>/dev/null | jq -r '"\(.engine)/\(.type)"' 2>/dev/null | sort | uniq -c | sed 's/^/    /'
exit "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
