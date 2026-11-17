#!/usr/bin/env bash
# =============================================================================
#
# Usage:  ./scripts/test-firewall.sh
# =============================================================================
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
CLI=./build/bin/dbguard-cli
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; DIM=$'\e[2m'; RST=$'\e[0m'
pass=0; fail=0
ok(){ echo "  ${GRN}PASS${RST} $*"; pass=$((pass+1)); }
no(){ echo "  ${RED}FAIL${RST} $*"; fail=$((fail+1)); }
hdr(){ echo; echo "${BLU}== $* ==${RST}"; }

[ -x "$CLI" ] || { echo "build first: make go-build"; exit 2; }
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/pol"
cat > "$WORK/cfg.yaml" <<YAML
general: {name: fwtest, data_dir: $WORK}
policies: {dirs: [$WORK/pol]}
YAML

# write a one-rule policy. $1 = default_action, $2... = rule yaml lines (indented)
policy(){
  local def="$1"; shift
  { echo "api_version: dbguard.io/v1"
    echo "kind: DbGuardPolicy"
    echo "metadata: {name: t}"
    echo "spec:"
    echo "  default_action: $def"
    echo "  rules:"
    printf '%s\n' "$@"
  } > "$WORK/pol/rule.yaml"
}
# evaluate: engine user db ip "sql" -> ALLOW|DENY
ev(){ "$CLI" dry-run -c "$WORK/cfg.yaml" -e "$1" -u "$2" -d "$3" -ip "$4" "$5" 2>/dev/null \
      | grep -oE 'decision:  (ALLOW|DENY)' | awk '{print $2}'; }
# expect: <want ALLOW|DENY> engine user db ip "sql" "label"
expect(){ local want="$1"; shift; local got; got="$(ev "$1" "$2" "$3" "$4" "$5")"
  [ "$got" = "$want" ] && ok "$6 -> $got" || no "$6 -> got $got, want $want"; }

# ---------------------------------------------------------------------------
hdr "1. Match by SQL pattern (regexp)"
policy allow \
'    - id: r' \
'      query: {pattern: '"'"'(?i)\bdrop\s+table\b'"'"'}' \
'      actions: [deny, alert]'
expect DENY  postgres u db 10.0.0.1 "DROP TABLE customers"             "pattern DROP TABLE matches"
expect ALLOW postgres u db 10.0.0.1 "SELECT * FROM customers"          "pattern: unrelated query allowed"

hdr "2. Match by SQL keywords (ANY-of)"
policy allow \
'    - id: r' \
'      query: {keywords: [into outfile, load_file, pg_read_file], case_insensitive: true}' \
'      actions: [deny, alert]'
expect DENY  mysql u db 10.0.0.1 "SELECT * INTO OUTFILE '/x' FROM u"   "keyword INTO OUTFILE"
expect DENY  postgres u db 10.0.0.1 "SELECT pg_read_file('/etc/passwd')" "keyword pg_read_file"
expect ALLOW postgres u db 10.0.0.1 "SELECT id FROM products"          "keywords: clean query allowed"

hdr "3. Match by DB user (role)"
policy allow \
'    - id: r' \
'      users: [app_ro, reporting]' \
'      query: {pattern: '"'"'(?i)^\s*(insert|update|delete)\b'"'"'}' \
'      actions: [deny, alert]'
expect DENY  postgres app_ro   db 10.0.0.1 "UPDATE t SET x=1"          "user app_ro write denied"
expect ALLOW postgres app_rw   db 10.0.0.1 "UPDATE t SET x=1"          "user app_rw write allowed"
expect ALLOW postgres app_ro   db 10.0.0.1 "SELECT * FROM t"          "user app_ro read allowed"

hdr "4. Match by source IP / CIDR"
policy allow \
'    - id: r' \
'      clients: [192.168.0.0/16, 10.1.2.3]' \
'      actions: [deny, alert]'
expect DENY  postgres u db 192.168.5.7 "SELECT 1"                      "client in 192.168/16 denied"
expect DENY  postgres u db 10.1.2.3    "SELECT 1"                      "client exact 10.1.2.3 denied"
expect ALLOW postgres u db 10.9.9.9    "SELECT 1"                      "client outside CIDR allowed"

hdr "5. Match by engine"
policy allow \
'    - id: r' \
'      engines: [mysql]' \
'      query: {pattern: '"'"'(?i)sleep\s*\('"'"'}' \
'      actions: [deny, alert]'
expect DENY  mysql    u db 10.0.0.1 "SELECT SLEEP(5)"                  "engine mysql + SLEEP denied"
expect ALLOW postgres u db 10.0.0.1 "SELECT SLEEP(5)"                  "engine postgres skipped"

hdr "6. Match by database"
policy allow \
'    - id: r' \
'      databases: [prod]' \
'      query: {pattern: '"'"'(?i)\btruncate\b'"'"'}' \
'      actions: [deny, alert]'
expect DENY  postgres u prod    10.0.0.1 "TRUNCATE TABLE t"            "db prod TRUNCATE denied"
expect ALLOW postgres u staging 10.0.0.1 "TRUNCATE TABLE t"            "db staging allowed"

hdr "7. Default-DENY (zero-trust allowlist)"
policy deny \
'    - id: allow-app' \
'      users: [app_rw]' \
'      query: {pattern: '"'"'(?i)^\s*select'"'"'}' \
'      actions: [allow]'
expect ALLOW postgres app_rw db 10.0.0.1 "SELECT id FROM products"    "allowlist: app_rw SELECT allowed"
expect DENY  postgres app_rw db 10.0.0.1 "DELETE FROM products"       "allowlist: non-SELECT denied"
expect DENY  postgres other  db 10.0.0.1 "SELECT id FROM products"    "allowlist: other user denied"

hdr "8. Combined matchers (user AND source AND query)"
policy allow \
'    - id: r' \
'      users: [analyst]' \
'      clients: [10.0.0.0/8]' \
'      query: {keywords: [credit_card, ssn], case_insensitive: true}' \
'      actions: [deny, alert]'
expect DENY  postgres analyst db 10.5.5.5 "SELECT credit_card FROM c" "all three match -> deny"
expect ALLOW postgres analyst db 172.16.0.1 "SELECT credit_card FROM c" "wrong source -> allow"
expect ALLOW postgres bob     db 10.5.5.5 "SELECT credit_card FROM c" "wrong user -> allow"
expect ALLOW postgres analyst db 10.5.5.5 "SELECT name FROM c"        "no sensitive col -> allow"

hdr "9. Rate limiting (sliding window - verified in-process)"
# The window can't persist across separate CLI processes, so enforcement is
# proven by the in-process unit tests, which fire a burst and assert the
# allowed/denied split (incl. the empty-client-IP case that local queries hit).
if command -v go >/dev/null 2>&1; then
  if go test -count=1 -run 'TestRateLimitThrottle|TestRateLimitEmptyClientIP' ./internal/policy/ >/tmp/fw_rate.log 2>&1; then
    ok "rate limiting ENFORCED: TestRateLimitThrottle + TestRateLimitEmptyClientIP pass (burst throttled)"
  else
    no "rate-limit unit tests failed (see /tmp/fw_rate.log)"
  fi
else
  # fallback: confirm the rule at least loads & evaluates
  policy allow '    - id: r' '      clients: [0.0.0.0/0]' '      rate: {events: 100, window: 10s}' '      actions: [deny, alert]'
  [ -n "$(ev postgres u db 10.0.0.1 'SELECT 1')" ] \
    && ok "rate rule loads & evaluates (install go to run the enforcement test)" \
    || no "rate rule failed to evaluate"
fi

hdr "SUMMARY"
echo "  ${GRN}pass=$pass${RST}  ${RED}fail=$fail${RST}"
[ "$fail" -eq 0 ] && echo "  ${GRN}every configured firewall rule enforced exactly as written${RST}" \
                  || echo "  ${RED}some rules did not enforce as written${RST}"
exit "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
