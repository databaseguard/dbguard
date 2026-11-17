#!/usr/bin/env bash
# test-policies.sh - exercise EVERY shipped policy rule, one assertion each.
#
# Two parts:
#   A. Deterministic rule checks via `dbguard-cli dry-run` (no daemon/DB needed):
#      every rule family is fired with a payload that must DENY, plus benign
#      queries that must ALLOW. This is the authoritative per-rule test.
#   B. Live rate-limit + inline-proxy block (needs the daemon running with
#      configs/dbguard.dev.yaml and the DBs seeded via scripts/setup-dbs.sh).
#
# Usage:
#   ./scripts/test-policies.sh            # A always; B if the proxy is reachable
#   SKIP_LIVE=1 ./scripts/test-policies.sh  # A only
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; cd "$REPO_ROOT"
CLI="build/bin/dbguard-cli"; CFG="configs/dbguard.dev.yaml"
PGPROXY_PORT="${PGPROXY_PORT:-6432}"; PGUSER_="${PGUSER_:-dbguard}"; PGPASS_="${PGPASS_:-dbguard}"; PGDB_="${PGDB_:-dbguard_test}"
pass=0; fail=0
GRN=$'\e[32m'; RED=$'\e[31m'; YEL=$'\e[33m'; BLU=$'\e[34m'; RST=$'\e[0m'
ok(){ echo "  ${GRN}PASS${RST} $*"; pass=$((pass+1)); }
no(){ echo "  ${RED}FAIL${RST} $*"; fail=$((fail+1)); }
hdr(){ echo; echo "${BLU}== $* ==${RST}"; }

[ -x "$CLI" ] || { echo "building dbguard-cli…"; make go-build >/dev/null 2>&1 || { echo "cannot build CLI"; exit 2; }; }

# verdict <engine> <user> <sql> -> prints DENY/ALLOW and the first matched rule
verdict(){ "$CLI" dry-run -c "$CFG" -e "$1" -u "$2" ${4:+-ip "$4"} "$3" 2>/dev/null; }
# must_deny <label> <expected-rule-substr> <engine> <user> <sql> [ip]
must_deny(){ local label=$1 want=$2 out; out="$(verdict "$3" "$4" "$5" "${6:-}")"
  if echo "$out" | grep -q 'decision:  DENY' && echo "$out" | grep -q "$want"
  then ok "$label -> DENY ($want)"; else no "$label -> expected DENY/$want, got: $(echo "$out" | grep decision)"; fi; }
# must_allow <label> <engine> <user> <sql>
must_allow(){ local label=$1 out; out="$(verdict "$2" "$3" "$4" "")"
  if echo "$out" | grep -q 'decision:  ALLOW'; then ok "$label -> ALLOW"; else no "$label -> expected ALLOW, got: $(echo "$out" | grep decision)"; fi; }

hdr "A. SQL-injection firewall (20-sql-firewall.yaml)"
must_deny "tautology (OR 1=1)"  sqli.tautology  postgres app "SELECT * FROM customers WHERE name='' OR 1=1 --"
must_deny "union extraction"    sqli.union      postgres app "SELECT id FROM customers UNION SELECT credit_card FROM customers"
must_deny "stacked DROP"        sqli.stacked    postgres app "SELECT 1; DROP TABLE customers"
must_deny "time-based blind"    sqli.timebased  postgres app "SELECT 1 FROM customers WHERE id=1 AND pg_sleep(5)"

hdr "B. Query firewall (60-query-firewall.yaml)"
must_deny "read-only user write"  fw.ro-no-writes          postgres app_ro "INSERT INTO customers(full_name) VALUES('x')"
must_deny "sensitive columns"     fw.sensitive-columns     postgres intern "SELECT ssn, credit_card FROM customers"
must_deny "file primitive"        fw.block-file-primitives mysql    app    "SELECT a FROM t INTO OUTFILE '/tmp/x'"
must_deny "destructive DDL"       rids.destructive_ddl     postgres app    "DROP TABLE customers"

hdr "C. Tenant isolation (40-tenant-isolation.yaml)"
must_deny "tenant_a_svc -> tenant_b table" tenant.b_isolation postgres tenant_a_svc "SELECT * FROM users_tenant_b"
must_deny "tenant_b_svc -> tenant_a table" tenant.a_isolation postgres tenant_b_svc "SELECT * FROM users_tenant_a"

hdr "D. PII protection (10-pii-protection.yaml)"
must_deny "bulk PII columns" pii. postgres app "SELECT credit_card, ssn, salary FROM customers"

hdr "E. Benign traffic must be ALLOWED (no false positives)"
must_allow "parameterized select" postgres app "SELECT id, full_name FROM customers WHERE id = 5"
must_allow "simple join"          postgres app "SELECT c.id, o.item FROM customers c JOIN orders o ON o.customer_id=c.id"
must_allow "aggregate"            postgres app "SELECT count(*) FROM orders"

if [ "${SKIP_LIVE:-0}" != 1 ] && command -v psql >/dev/null 2>&1; then
  hdr "F. LIVE rate limiting via the inline proxy (port ${PGPROXY_PORT})"
  if PGPASSWORD="$PGPASS_" psql "host=127.0.0.1 port=${PGPROXY_PORT} dbname=${PGDB_} user=${PGUSER_} sslmode=disable" -tAc 'SELECT 1' >/dev/null 2>&1; then

    sql="$(for _ in $(seq 1 70); do echo "SELECT count(*) FROM customers;"; done)"
    out="$(printf '%s\n' "$sql" | PGPASSWORD="$PGPASS_" psql "host=127.0.0.1 port=${PGPROXY_PORT} dbname=${PGDB_} user=${PGUSER_} sslmode=disable" -tA 2>&1)"
    denied="$(echo "$out" | grep -c "blocked by policy")"
    allowed="$(echo "$out" | grep -cE '^[0-9]+$')"
    if [ "$denied" -gt 0 ] && [ "$allowed" -gt 0 ]; then
      ok "rate limit tripped after the threshold (allowed=$allowed denied=$denied)"
    else
      no "rate limit not observed (allowed=$allowed denied=$denied) - restart the daemon so the window is fresh, then rerun"
    fi
    hdr "G. LIVE inline block via the proxy"
    out="$(PGPASSWORD="$PGPASS_" psql "host=127.0.0.1 port=${PGPROXY_PORT} dbname=${PGDB_} user=${PGUSER_} sslmode=disable" -c "SELECT id FROM customers UNION SELECT credit_card FROM customers" 2>&1)"
    echo "$out" | grep -q "blocked by policy" && ok "UNION blocked inline at the proxy" || no "UNION not blocked at the proxy: $out"
  else
    echo "  ${YEL}SKIP${RST} proxy not reachable on ${PGPROXY_PORT} - start the daemon with ${CFG}"
  fi
fi

echo; echo "${BLU}== SUMMARY ==${RST}"
echo "  ${GRN}pass=$pass${RST}  ${RED}fail=$fail${RST}"
[ "$fail" -eq 0 ] && echo "  ${GRN}all policy checks passed${RST}" || echo "  ${RED}policy failures detected${RST}"
exit "$fail"
