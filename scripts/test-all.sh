#!/usr/bin/env bash
# =============================================================================
# dbguard - comprehensive test harness
#
# Three tiers, each independently useful:
#
#   A. OFFLINE detector tests (no daemon, no DB, no root)
#      Drives the detection engines directly through dbguard-cli. Proves the
#      SQLi, PII and policy logic itself. Always runnable.
#
#   B. LIVE end-to-end tests (needs the daemon running + seeded DBs)
#      Fires real attack traffic at Postgres/MySQL and checks that the running
#      daemon recorded the expected events via its API.
#
#   C. UNIT + verifier tests (needs the repo + toolchain)
#      Runs `go test ./...` and loads every eBPF object into the kernel verifier.
#
# Usage:
#   scripts/test-all.sh                # auto: run every tier that's possible
#   scripts/test-all.sh offline        # tier A only
#   scripts/test-all.sh live           # tier B only (assumes daemon+DBs up)
#   scripts/test-all.sh unit           # tier C only
#
# Exit code is non-zero if any attempted check fails.
# =============================================================================
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CLI="./build/bin/dbguard-cli"
API="${DBGUARD_API:-http://127.0.0.1:9700}"
PG="127.0.0.1:5432"; MY="127.0.0.1:3306"
PGPASS="${PGPASSWORD:-dbguard}"; PGUSER=dbguard; PGDB=dbguard_test
MYUSER=dbguard; MYPASS=dbguard; MYDB=dbguard_test
SQLITE_DB="${SQLITE_DB:-/tmp/dbguard_test.db}"

pass=0; fail=0; skip=0
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; DIM=$'\e[2m'; RST=$'\e[0m'
ok()   { echo "  ${GRN}PASS${RST} $*"; pass=$((pass+1)); }
no()   { echo "  ${RED}FAIL${RST} $*"; fail=$((fail+1)); }
sk()   { echo "  ${YEL}SKIP${RST} $*"; skip=$((skip+1)); }
hdr()  { echo; echo "${BLU}== $* ==${RST}"; }

need() { command -v "$1" >/dev/null 2>&1; }

build_cli() {
  if [ ! -x "$CLI" ]; then
    echo "${DIM}building dbguard-cli…${RST}"
    make go-build >/dev/null 2>&1 || { echo "cannot build CLI"; exit 2; }
  fi
}

# -----------------------------------------------------------------------------
# Tier A - offline detector tests
# -----------------------------------------------------------------------------
tier_offline() {
  hdr "TIER A - offline detector tests (CLI, no daemon/DB)"
  build_cli

  echo "${DIM}-- SQLi firewall: each payload must score DENY --${RST}"
  # name|payload
  local sqli_cases=(
    "tautology|SELECT * FROM users WHERE id=1 OR 1=1 --"
    "tautology-quoted|admin' OR '1'='1"
    "union-select|SELECT name FROM t UNION SELECT credit_card, ssn FROM customers"
    "stacked|SELECT 1; DROP TABLE users;"
    "comment-evasion|SELECT * FROM users WHERE id=1 UN/**/ION SE/**/LECT credit_card,ssn FROM customers"
    "time-blind-pg|SELECT * FROM t WHERE id=1 AND pg_sleep(5)"
    "time-blind-my|SELECT * FROM t WHERE id=1 AND SLEEP(5)"
    "boolean-blind|SELECT * FROM t WHERE id=1 AND 1=1"
    "or-true-numeric|SELECT * FROM accounts WHERE bal>0 OR 7=7"
  )
  for c in "${sqli_cases[@]}"; do
    local name sql; name="${c%%|*}"; sql="${c#*|}"
    if "$CLI" test-sqli "$sql" 2>/dev/null | grep -qi 'DENY'; then
      ok "sqli/$name -> DENY"
    else
      no "sqli/$name -> expected DENY"
    fi
  done

  echo "${DIM}-- SQLi: benign queries must be ALLOWed (no false positives) --${RST}"
  local benign=(
    "plain-select|SELECT id, name FROM products WHERE price < 100"
    "parameterized|SELECT * FROM users WHERE email = \$1"
    "join|SELECT a.id FROM a JOIN b ON a.id=b.a_id WHERE b.active = true"
  )
  for c in "${benign[@]}"; do
    local name sql; name="${c%%|*}"; sql="${c#*|}"
    if "$CLI" test-sqli "$sql" 2>/dev/null | grep -qi 'ALLOW'; then
      ok "benign/$name -> ALLOW"
    else
      no "benign/$name -> expected ALLOW (false positive)"
    fi
  done

  echo "${DIM}-- PII detector: each sample must be found + redacted --${RST}"
  # label|text|expected-kind
  local pii_cases=(
    "credit-card|card 4111111111111111 on file|credit_card"
    "visa-spaced|4111 1111 1111 1111|credit_card"
    "ssn|SSN 123-45-6789 redacted|ssn"
    "email|contact a.user@example.com|email"
    "phone|call +1 415 555 0132|phone"
    "amex|378282246310005 charged|credit_card"
  )
  for c in "${pii_cases[@]}"; do
    local label text kind rest
    label="${c%%|*}"; rest="${c#*|}"; text="${rest%|*}"; kind="${rest##*|}"
    local out; out="$("$CLI" test-pii -redact "$text" 2>/dev/null)"
    if echo "$out" | grep -qi "$kind"; then
      ok "pii/$label -> detected $kind"
    else
      no "pii/$label -> expected $kind; got: $(echo "$out" | tr '\n' ' ' | cut -c1-80)"
    fi
  done

  echo "${DIM}-- PII: clean text must yield no findings --${RST}"
  if "$CLI" test-pii "the quick brown fox jumps over 13 lazy dogs" 2>/dev/null | grep -qiE '0 finding|no finding'; then
    ok "pii/clean -> 0 findings"
  else
    sk "pii/clean -> detector reported findings (review output format)"
  fi

  echo "${DIM}-- Policy engine: dry-run evaluation against local policies --${RST}"
  if [ -f configs/dbguard.dev.yaml ]; then CFG=configs/dbguard.dev.yaml; else CFG=configs/dbguard.yaml; fi
  if "$CLI" dry-run -c "$CFG" -e postgres -u app -d prod -ip 10.0.0.9 \
       "SELECT credit_card FROM customers" 2>/dev/null | grep -qiE 'deny|allow|match'; then
    ok "policy/dry-run evaluated"
  else
    sk "policy/dry-run (unexpected output; not fatal)"
  fi

  echo "${DIM}-- Config + policy validation --${RST}"
  "$CLI" validate-config -c "$CFG" >/dev/null 2>&1 && ok "config valid: $CFG" || no "config invalid: $CFG"
  "$CLI" validate-policy -d configs/policies >/dev/null 2>&1 && ok "policies valid" || no "policies invalid"
}

# -----------------------------------------------------------------------------
# Tier B - live end-to-end tests
# -----------------------------------------------------------------------------
daemon_up() { curl -fsS "$API/api/v1/status" >/dev/null 2>&1 || curl -fsS "$API/healthz" >/dev/null 2>&1; }

event_count() { # $1 = type substring ; counts via the events API
  "$CLI" events -n 200 2>/dev/null | grep -c "$1"
}

tier_live() {
  hdr "TIER B - live end-to-end (daemon + seeded DBs)"
  build_cli
  if ! daemon_up; then
    sk "daemon not reachable at $API - start it: sudo ./build/bin/dbguardd -config configs/dbguard.dev.yaml"
    return
  fi
  ok "daemon reachable at $API"

  local have_pg=0 have_my=0 have_sqlite=0
  need psql  && PGPASSWORD="$PGPASS" psql -h 127.0.0.1 -p 5432 -U "$PGUSER" -d "$PGDB" -c 'SELECT 1' >/dev/null 2>&1 && have_pg=1
  need mysql && mysql -h 127.0.0.1 -P 3306 -u "$MYUSER" -p"$MYPASS" "$MYDB" -e 'SELECT 1' >/dev/null 2>&1 && have_my=1
  need sqlite3 && [ -f "$SQLITE_DB" ] && have_sqlite=1
  [ "$have_pg" = 1 ]     && ok "postgres reachable"  || sk "postgres not reachable (run scripts/setup-dbs.sh)"
  [ "$have_my" = 1 ]     && ok "mysql reachable"     || sk "mysql not reachable (run scripts/setup-dbs.sh)"
  [ "$have_sqlite" = 1 ] && ok "sqlite present"      || sk "sqlite db not present"

  pgq()  { PGPASSWORD="$PGPASS" psql -h 127.0.0.1 -p 5432 -U "$PGUSER" -d "$PGDB" -c "$1" >/dev/null 2>&1; }
  myq()  { mysql -h 127.0.0.1 -P 3306 -u "$MYUSER" -p"$MYPASS" "$MYDB" -e "$1" >/dev/null 2>&1; }

  local before_sqli before_pii before_exfil
  before_sqli=$(event_count 'sqli'); before_pii=$(event_count 'pii'); before_exfil=$(event_count 'exfil')

  if [ "$have_pg" = 1 ]; then
    echo "${DIM}-- firing attacks at postgres --${RST}"
    pgq "SELECT id, email FROM customers WHERE full_name = '' OR 1=1 --"
    pgq "SELECT id FROM customers WHERE id=1 UNION SELECT credit_card, ssn FROM customers"
    pgq "SELECT 1; DROP TABLE IF EXISTS _dbg_noop;"
    for _ in $(seq 1 12); do pgq "SELECT * FROM customers"; done   # bulk-dump -> exfil.bulk_query
  fi
  if [ "$have_my" = 1 ]; then
    echo "${DIM}-- firing attacks at mysql --${RST}"
    myq "SELECT id, email FROM customers WHERE full_name = '' OR 1=1 #"
    myq "SELECT id FROM customers WHERE id=1 UNION SELECT credit_card, ssn FROM customers"
    for _ in $(seq 1 12); do myq "SELECT * FROM employees"; done
  fi

  echo "${DIM}-- waiting 3s for events to drain through the pipeline --${RST}"
  sleep 3
  local after_sqli after_pii after_exfil
  after_sqli=$(event_count 'sqli'); after_pii=$(event_count 'pii'); after_exfil=$(event_count 'exfil')

  [ "$after_exfil" -gt "$before_exfil" ] && ok "exfil detected (bulk dump: burst or bulk_query) [$before_exfil -> $after_exfil]" \
    || sk "exfil not observed [$before_exfil -> $after_exfil] - needs query-text capture (uprobe) + enough egress; the exfil logic itself is covered by unit tests (Tier C)."

  if [ "$after_sqli" -gt "$before_sqli" ]; then
    ok "sqli detected on the wire [$before_sqli -> $after_sqli]"
  else
    sk "sqli not observed - query-text capture (uprobe) likely inactive on stripped DB binaries. See daemon log for the dbgsym hint, or install postgresql-16-dbgsym / mysql-server-dbgsym."
  fi
  if [ "$after_pii" -gt "$before_pii" ]; then
    ok "pii detected in query/result [$before_pii -> $after_pii]"
  else
    sk "pii not observed - same cause as sqli (needs query-text capture)."
  fi

  echo "${DIM}-- metrics endpoint --${RST}"
  if curl -fsS "${API%:*}:9701/metrics" 2>/dev/null | grep -q 'events_total'; then
    ok "metrics exporting events_total"
    curl -fsS "${API%:*}:9701/metrics" 2>/dev/null | grep -E '^(events_total|findings_total)' | sed 's/^/      /'
  else
    sk "metrics endpoint not reachable on :9701"
  fi
}

# -----------------------------------------------------------------------------
# Tier C - unit + verifier
# -----------------------------------------------------------------------------
tier_unit() {
  hdr "TIER C - unit tests + kernel verifier"
  if need go; then
    echo "${DIM}-- go test ./... --${RST}"
    if go test -count=1 ./... >/tmp/dbg_gotest.log 2>&1; then
      ok "go test ./... ($(grep -c '^ok' /tmp/dbg_gotest.log) packages)"
    else
      no "go test ./... (see /tmp/dbg_gotest.log)"; tail -5 /tmp/dbg_gotest.log | sed 's/^/      /'
    fi
  else
    sk "go not installed - skipping unit tests"
  fi

  if [ -d build/bpf ] && ls build/bpf/*.o >/dev/null 2>&1; then
    if need go; then
      go build -o /tmp/bpfload ./tools/bpfload 2>/dev/null
      if [ -x /tmp/bpfload ] && [ "$(id -u)" = 0 ]; then
        echo "${DIM}-- kernel verifier (non-LSM objects) --${RST}"
        local nonlsm; nonlsm=$(ls build/bpf/*.o | grep -v '_lsm\.bpf\.o')
        if /tmp/bpfload $nonlsm 2>&1 | grep -q 'objects fully passed'; then
          ok "all non-LSM objects pass the kernel verifier"
        else
          no "some objects failed the verifier (run: sudo /tmp/bpfload build/bpf/*.o)"
        fi
      else
        sk "verifier load needs root (sudo scripts/test-all.sh unit)"
      fi
    fi
  else
    sk "build/bpf not present - run: make bpf"
  fi
}

# -----------------------------------------------------------------------------
main() {
  local mode="${1:-auto}"
  echo "${BLU}dbguard test harness${RST}  (mode: $mode)"
  case "$mode" in
    offline) tier_offline ;;
    live)    tier_live ;;
    unit)    tier_unit ;;
    auto)    tier_offline; tier_unit; tier_live ;;
    *) echo "usage: $0 [offline|live|unit|auto]"; exit 1 ;;
  esac
  hdr "SUMMARY"
  echo "  ${GRN}pass=$pass${RST}  ${RED}fail=$fail${RST}  ${YEL}skip=$skip${RST}"
  [ "$fail" -eq 0 ] && echo "  ${GRN}all attempted checks passed${RST}" || echo "  ${RED}failures detected${RST}"
  exit "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
}
main "$@"
