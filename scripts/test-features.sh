#!/usr/bin/env bash
# =============================================================================
# test-features.sh - ONE script that exercises EVERY dbguard feature and prints
# a PASS/FAIL/SKIP verdict per capability.
#
# Tiers (each runs only if its prerequisites are present):
#   A. OFFLINE detectors & firewall  - CLI only, no daemon/DB/root.
#        SQLi detector, PII detector+redaction, and the full query firewall
#        (allow/deny, read-only enforcement, DDL block, file-primitive block,
#         column protection, source/CIDR, rate limiting).
#   B. UNIT + kernel verifier        - go test ./... and bpfload (root for load).
#   C. LIVE end-to-end               - daemon + seeded Postgres/MySQL:
#        query capture, SQLi, PII, exfil bulk-dump, RIDS file-integrity,
#        Prometheus metrics, admin API. (MySQL/Postgres auto-detected.)
#
# Usage:
#   ./scripts/test-features.sh            # auto: run every tier possible
#   ./scripts/test-features.sh offline    # tier A only (no root/DB needed)
#   sudo ./scripts/test-features.sh live  # tier C only
#   ./scripts/test-features.sh unit       # tier B only
#
# Exit non-zero if any attempted check fails.
# =============================================================================
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
CLI=./build/bin/dbguard-cli
DBGUARDD=./build/bin/dbguardd
CFG="${DBGUARD_CONFIG:-configs/dbguard.dev.yaml}"
AUDIT_DIR=.dbguard-state/audit
TFLOG="$(mktemp -t tf_go.XXXXXX)"; TFDLOG="$(mktemp -t tf_daemon.XXXXXX)"
trap 'rm -f "$TFLOG" "$TFDLOG" "${_countpy:-}"' EXIT
API=http://127.0.0.1:9700; MET=http://127.0.0.1:9701/metrics
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; BLU=$'\e[34m'; DIM=$'\e[2m'; RST=$'\e[0m'
pass=0; fail=0; skip=0
ok(){ echo "  ${GRN}PASS${RST} $*"; pass=$((pass+1)); }
no(){ echo "  ${RED}FAIL${RST} $*"; fail=$((fail+1)); }
sk(){ echo "  ${YEL}SKIP${RST} $*"; skip=$((skip+1)); }
hdr(){ echo; echo "${BLU}== $* ==${RST}"; }
need(){ command -v "$1" >/dev/null 2>&1; }
gt0(){ local n="${1:-0}"; [ -z "$n" ] && n=0; [ "$n" -gt 0 ] 2>/dev/null; }

build(){ [ -x "$CLI" ] || { echo "${DIM}building…${RST}"; make go-build >/dev/null 2>&1 || { echo "build failed"; exit 2; }; }; }

# ---------------------------------------------------------------------------
# helpers to evaluate a query against the firewall (offline)
fw(){ # engine user db ip sql -> prints ALLOW|DENY
  "$CLI" dry-run -c "$CFG" -e "$1" -u "$2" -d "$3" -ip "$4" "$5" 2>/dev/null \
    | grep -oE 'decision:  (ALLOW|DENY)' | awk '{print $2}'
}
sqli(){ "$CLI" test-sqli "$1" 2>/dev/null | grep -oiE 'DENY|ALLOW' | head -1; }
piik(){ "$CLI" test-pii "$1" 2>/dev/null; }

# ---------------------------------------------------------------------------
tier_offline(){
  hdr "TIER A - detectors & query firewall (offline, CLI only)"
  build

  echo "${DIM}-- SQLi injection firewall --${RST}"
  for p in \
    "SELECT * FROM u WHERE a=1 OR 1=1 --" \
    "admin' OR '1'='1" \
    "SELECT a FROM t UNION SELECT credit_card,ssn FROM customers" \
    "SELECT 1; DROP TABLE users;" \
    "SELECT * FROM t WHERE id=1 AND SLEEP(5)" \
    "SELECT * FROM accounts WHERE bal>0 OR 7=7"; do
    [ "$(sqli "$p")" = "DENY" ] && ok "sqli DENY: ${p:0:40}" || no "sqli expected DENY: ${p:0:40}"
  done
  for p in "SELECT id FROM products WHERE price<100" "SELECT * FROM users WHERE email=\$1"; do
    [ "$(sqli "$p")" = "ALLOW" ] && ok "sqli ALLOW (no FP): ${p:0:40}" || no "sqli false-positive: ${p:0:40}"
  done

  echo "${DIM}-- PII detector + redaction --${RST}"
  piik "card 4111111111111111"      | grep -qi credit_card && ok "pii credit card" || no "pii credit card"
  piik "SSN 123-45-6789"            | grep -qi ssn         && ok "pii ssn"         || no "pii ssn"
  piik "mail a.user@example.com"    | grep -qi email       && ok "pii email"       || no "pii email"
  "$CLI" test-pii -redact "card 4111111111111111" 2>/dev/null | grep -q '\*\*\*\*' && ok "pii redaction" || no "pii redaction"

  echo "${DIM}-- Query firewall: allow/deny by query, user, source, rate --${RST}"
  [ "$(fw postgres app_ro prod 10.0.0.1 'DELETE FROM customers WHERE id=1')" = "DENY" ] \
    && ok "firewall: read-only user write -> DENY" || no "firewall: read-only write should DENY"
  [ "$(fw postgres app_rw prod 10.0.0.1 'SELECT id,name FROM products')" = "ALLOW" ] \
    && ok "firewall: app_rw SELECT -> ALLOW" || no "firewall: app_rw SELECT should ALLOW"
  [ "$(fw postgres root prod 10.0.0.1 'DROP TABLE customers')" = "DENY" ] \
    && ok "firewall: DDL on prod -> DENY" || no "firewall: DDL on prod should DENY"
  local outfile_q="SELECT * INTO OUTFILE '/x' FROM u"
  [ "$(fw mysql app prod 10.0.0.1 "$outfile_q")" = "DENY" ] \
    && ok "firewall: file-primitive (INTO OUTFILE) -> DENY" || no "firewall: INTO OUTFILE should DENY"

  echo "${DIM}-- Query firewall: rate limiting (sliding window) --${RST}"
  # use a throwaway policy: 5 events / 1m from any client
  local rp; rp="$(mktemp -d)"; mkdir -p "$rp/pol"
  cat > "$rp/pol/rl.yaml" <<YAML
api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata: {name: rl}
spec:
  default_action: allow
  rules:
    - id: rl
      clients: [0.0.0.0/0]
      rate: {events: 5, window: 1m}
      actions: [deny, alert]
YAML
  cat > "$rp/cfg.yaml" <<YAML
general: {name: t, data_dir: $rp}
policies: {dirs: [$rp/pol]}
YAML
  # NOTE: each CLI call is a fresh process, so the window does not persist
  # across calls - rate limiting is proven in the unit test
  # (TestRateLimitThrottle). Here we just confirm the rule loads & evaluates.
  if "$CLI" dry-run -c "$rp/cfg.yaml" -ip 10.0.0.9 "SELECT 1" >/dev/null 2>&1; then
    ok "firewall: rate rule loads & evaluates (throttle proven in unit test)"
  else
    no "firewall: rate rule failed to evaluate"
  fi
  rm -rf "$rp"

  echo "${DIM}-- Config & policy validation --${RST}"
  "$CLI" validate-config -c "$CFG" >/dev/null 2>&1 && ok "config validates" || no "config invalid"
  "$CLI" validate-policy -d configs/policies >/dev/null 2>&1 && ok "all policies validate" || no "policy invalid"
}

# ---------------------------------------------------------------------------
tier_unit(){
  hdr "TIER B - unit tests + kernel verifier"
  if need go; then
    if go test -count=1 ./... >"$TFLOG" 2>&1; then
      ok "go test ./... ($(grep -c '^ok' /tmp/tf_go.log) packages)"
    else
      no "go test ./... (see $TFLOG)"; grep -E 'FAIL|panic' "$TFLOG" | head -3 | sed 's/^/      /'
    fi
  else sk "go not installed"; fi

  if [ -d build/bpf ] && need go; then
    go build -o /tmp/bpfload ./tools/bpfload 2>/dev/null
    if [ -x /tmp/bpfload ] && [ "$(id -u)" = 0 ]; then
      if /tmp/bpfload $(ls build/bpf/*.o | grep -v '_lsm\.bpf\.o') 2>&1 | grep -q 'objects fully passed'; then
        ok "all non-LSM eBPF objects pass the kernel verifier"
      else no "some eBPF objects failed the verifier"; fi
    else sk "verifier load needs root (sudo … unit)"; fi
  else sk "build/bpf missing - run make bpf"; fi
}

# ---------------------------------------------------------------------------
daemon_up(){ curl -fsS "$API/api/v1/status" >/dev/null 2>&1 || curl -fsS "$API/healthz" >/dev/null 2>&1; }
# Count audit records by finding kind/type, optionally filtered by engine.
# Pure Python (no jq). Writes a tiny helper to a temp file once.
_countpy="$(mktemp -t tfcount.XXXXXX.py)"
cat > "$_countpy" <<'PYEOF'
import sys, glob, json, os
from collections import Counter
d    = sys.argv[1]
mode = sys.argv[2]
key  = sys.argv[3] if len(sys.argv) > 3 else ""
eng  = sys.argv[4] if len(sys.argv) > 4 else ""

def events():
    for fn in glob.glob(os.path.join(d, "*.jsonl")):
        try:
            for line in open(fn):
                try:
                    yield json.loads(line)
                except Exception:
                    continue
        except OSError:
            continue

if mode == "breakdown":
    c = Counter()
    for e in events():
        c[str(e.get("engine")) + "/" + str(e.get("type"))] += 1
    for k, v in sorted(c.items()):
        print("    %4d %s" % (v, k))
else:
    n = 0
    for e in events():
        if eng and e.get("engine") != eng:
            continue
        if mode == "find":
            if any(f.get("kind") == key for f in e.get("findings", [])):
                n += 1
        elif e.get("type") == key:
            n += 1
    print(n)
PYEOF
afind(){ python3 "$_countpy" "$AUDIT_DIR" find "$1" "${2:-}"; }
atype(){ python3 "$_countpy" "$AUDIT_DIR" type "$1" "${2:-}"; }

tier_live(){
  hdr "TIER C - live end-to-end (daemon + seeded DBs)"
  [ "$(id -u)" = 0 ] || { sk "live tier needs root (sudo … live)"; return; }

  build
  [ -x "$DBGUARDD" ] || { make go-build >/dev/null 2>&1; }

  pkill -f 'dbguardd -config' 2>/dev/null && sleep 1
  rm -rf "$AUDIT_DIR"; mkdir -p "$AUDIT_DIR"
  "$DBGUARDD" -config "$CFG" >"$TFDLOG" 2>&1 &
  local DPID=$!
  trap 'kill -INT "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null' RETURN
  for i in $(seq 1 30); do daemon_up && break; sleep 0.5; done
  daemon_up && ok "daemon started + admin API up" || { no "daemon did not come up"; return; }
  sleep 2   # let uprobe attach lines flush to the log before we count them

  local pg_at my_at
  pg_at=$(grep -c 'engine=postgres' <(grep "query auditing active" "$TFDLOG"))
  my_at=$(grep -c 'engine=mysql' <(grep "query auditing active" "$TFDLOG"))
  echo "  ${DIM}uprobe attach: postgres=$pg_at mysql=$my_at${RST}"

  local have_pg=0 have_my=0
  need psql  && PGPASSWORD=dbguard psql -h 127.0.0.1 -p 5432 -U dbguard -d dbguard_test -c 'SELECT 1' >/dev/null 2>&1 && have_pg=1
  need mysql && mysql -h 127.0.0.1 -P 3306 -u dbguard -pdbguard dbguard_test -e 'SELECT 1' >/dev/null 2>&1 && have_my=1

  pgq(){ PGPASSWORD=dbguard psql -h 127.0.0.1 -p 5432 -U dbguard -d dbguard_test -c "$1" >/dev/null 2>&1; }
  myq(){ mysql -h 127.0.0.1 -P 3306 -u dbguard -pdbguard dbguard_test -e "$1" >/dev/null 2>&1; }

  if [ "$have_pg" = 1 ]; then
    pgq "SELECT * FROM customers WHERE full_name='' OR 1=1 --"
    pgq "SELECT id FROM customers WHERE id=1 UNION SELECT credit_card, ssn FROM customers"
    pgq "SELECT 1; DROP TABLE IF EXISTS _t;"
    pgq "SELECT pg_sleep(1)"
    pgq "SELECT * FROM customers WHERE ssn='123-45-6789' AND card='4111111111111111'"
    for _ in $(seq 1 12); do pgq "SELECT * FROM customers"; done
  else sk "postgres not reachable (scripts/setup-dbs.sh)"; fi

  if [ "$have_my" = 1 ] && [ "$my_at" -gt 0 ]; then
    myq "SELECT * FROM customers WHERE name='' OR 1=1 #"
    myq "SELECT id FROM customers WHERE id=1 UNION SELECT credit_card, ssn FROM customers"
    myq "SELECT * FROM customers WHERE ssn='123-45-6789' AND card='4111111111111111'"
    for _ in $(seq 1 12); do myq "SELECT * FROM employees"; done
  elif [ "$have_my" = 1 ]; then sk "mysql reachable but query-audit uprobe not attached"
  else sk "mysql not reachable"; fi

  sleep 3
  # Postgres assertions
  if [ "$have_pg" = 1 ]; then
    gt0 "$(afind sqli.tautology postgres)"   && ok "pg SQLi tautology"   || no "pg SQLi tautology"
    gt0 "$(afind sqli.union_select postgres)" && ok "pg SQLi UNION"       || no "pg SQLi UNION"
    gt0 "$(afind sqli.time_based postgres)"  && ok "pg SQLi time-based"  || no "pg SQLi time-based"
    gt0 "$(afind pii.credit_card postgres)"  && ok "pg PII credit card"  || no "pg PII credit card"
    gt0 "$(afind pii.ssn_us postgres)"       && ok "pg PII SSN"          || no "pg PII SSN"
    gt0 "$(afind exfil.bulk_query postgres)" && ok "pg exfil bulk dump"  || no "pg exfil bulk dump"
  fi
  # MySQL assertions
  if [ "$have_my" = 1 ] && [ "$my_at" -gt 0 ]; then
    gt0 "$(afind sqli.tautology mysql)"  && ok "mysql SQLi tautology" || no "mysql SQLi tautology"
    gt0 "$(afind sqli.union_select mysql)" && ok "mysql SQLi UNION"   || no "mysql SQLi UNION"
    { gt0 "$(afind pii.credit_card mysql)" || gt0 "$(atype pii.detection mysql)"; } && ok "mysql PII" || no "mysql PII"
  fi
  # engine-independent
  gt0 "$(atype query.audit)" && ok "query auditing (capture→decode→store)" || no "query auditing"
  grep -q 'fim baseline established' "$TFDLOG" && ok "RIDS file-integrity baseline" || sk "RIDS baseline not logged"
  curl -fsS "$MET" 2>/dev/null | grep -q events_total && ok "Prometheus metrics" || no "metrics"
  "$CLI" events -n 3 >/dev/null 2>&1 && ok "admin API /events" || no "admin API"

  echo "  ${DIM}audit breakdown:${RST}"
  python3 "$_countpy" "$AUDIT_DIR" breakdown "" 2>/dev/null
}

main(){
  local mode="${1:-auto}"
  echo "${BLU}dbguard - full feature test${RST} (mode: $mode)"
  case "$mode" in
    offline) tier_offline ;;
    unit)    tier_unit ;;
    live)    tier_live ;;
    auto)    tier_offline; tier_unit; tier_live ;;
    *) echo "usage: $0 [offline|unit|live|auto]"; exit 1 ;;
  esac
  hdr "SUMMARY"
  echo "  ${GRN}pass=$pass${RST}  ${RED}fail=$fail${RST}  ${YEL}skip=$skip${RST}"
  [ "$fail" -eq 0 ] && echo "  ${GRN}all attempted checks passed${RST}" || echo "  ${RED}failures detected${RST}"
  exit "$([ "$fail" -eq 0 ] && echo 0 || echo 1)"
}
main "$@"
