#!/usr/bin/env bash
# DBGuard local attack simulation.
#
# Fires a scripted set of hostile-but-safe queries against the databases
# provisioned by scripts/setup-dbs.sh, printing the detection each step is
# expected to produce. Requires the agent to be running
# (sudo ./build/bin/dbguardd -config configs/dbguard.yaml).
#
# Sections are skipped gracefully when the matching database is absent.
set -euo pipefail

PG_HOST="127.0.0.1"; PG_PORT="${PG_PORT:-5432}"
MY_HOST="127.0.0.1"; MY_PORT="${MYSQL_PORT:-3306}"
export PGUSER="dbguard" PGPASSWORD="dbguard" PGDATABASE="dbguard_test"

BENIGN_TABLE="_dbguard_demo_noop"   # stacked-query target that must not exist

log()  { echo "[demo] $*"; }
step() { echo; echo "== $* =="; }
expected() { echo "   EXPECTED DETECTION: $*"; }
note()  { echo "   (skipped: $*)"; }

pg_up() {
    command -v psql >/dev/null 2>&1 && \
        pg_isready -h "$PG_HOST" -p "$PG_PORT" -q >/dev/null 2>&1
}

my_up() {
    command -v mysql >/dev/null 2>&1 && \
        mysqladmin ping -h "$MY_HOST" -P "$MY_PORT" -u dbguard -pdbguard --silent >/dev/null 2>&1
}

# Run a PostgreSQL statement; deny actions may reject it, which still counts
# as a successful simulation, so failures are swallowed on purpose.
pg_try() {
    echo "   pg> $1"
    PGPASSWORD="$PGPASSWORD" psql -h "$PG_HOST" -p "$PG_PORT" -U "$PGUSER" \
        -d "$PGDATABASE" -c "$1" >/dev/null 2>&1 || true
}

my_try() {
    echo "   mysql> $1"
    mysql -h "$MY_HOST" -P "$MY_PORT" -u dbguard -pdbguard dbguard_test \
        -e "$1" >/dev/null 2>&1 || true
}

banner() {
    cat <<'EOF'
DBGuard attack simulation
=========================
Make sure the agent is running and watching ports 5432/3306, then watch
findings with: ./build/bin/dbguard-cli events -n 20
EOF
}

sqli_section() {
    step "SQL injection: tautology bypass"
    pg_try  "SELECT id, email FROM customers WHERE full_name = '' OR 1=1 --"
    my_try  "SELECT id, email FROM customers WHERE full_name = '' OR 1=1 #"
    expected "sqli.attempt (rule sqli.tautology, severity critical, deny)"

    step "SQL injection: UNION extraction of PII columns"
    pg_try  "SELECT id, full_name FROM customers WHERE id = 1 UNION SELECT credit_card, ssn FROM customers"
    my_try  "SELECT id, name FROM customers WHERE id = 1 UNION SELECT credit_card, ssn FROM customers"
    expected "sqli.attempt (rule sqli.union) + pii.detection (credit_card/ssn columns)"

    step "SQL injection: stacked destructive statement"
    pg_try  "SELECT 1; DROP TABLE IF EXISTS ${BENIGN_TABLE};"
    my_try  "SELECT 1; DROP TABLE IF EXISTS ${BENIGN_TABLE};"
    expected "sqli.attempt (rule sqli.stacked, severity critical)"

    step "SQL injection: time-based blind"
    log "sleeping ~3-5s (time-based payloads are slow by design)"
    pg_try "SELECT pg_sleep(3);"
    my_try "SELECT SLEEP(5);"
    expected "sqli.attempt (rule sqli.timebased, severity high)"
}

exfil_section() {
    step "Bulk dump: repeated SELECT * over PII tables"
    local i
    for i in $(seq 1 10); do
        pg_try "SELECT * FROM customers"
        my_try "SELECT * FROM employees"
    done
    pg_try "\copy (SELECT * FROM customers) TO '/dev/null'"
    expected "exfil.burst (bulk dump breaker) + pii.bulk_select / exfil.bulk rate alerts"
}

rids_section() {
    step "RIDS: shell execution by the database service account"
    if [ "$(id -u)" -ne 0 ]; then
        note "requires root; re-run with sudo"
        return 0
    fi
    if id postgres >/dev/null 2>&1; then
        if command -v runuser >/dev/null 2>&1; then
            runuser -u postgres -- /bin/sh -c 'id' || true
        else
            su -s /bin/sh postgres -c 'id' || true
        fi
        expected "rids.execve (shell spawned by postgres service account)"
    else
        note "no postgres service account on this host"
    fi
}

outro() {
    echo
    echo "== summary =="
    log "all attempted sections complete"
    cat <<'EOF'
Inspect results:
  ./build/bin/dbguard-cli events -n 20
  tail -n 20 /var/log/dbguard/alerts.jsonl
  curl -s localhost:9701/metrics | grep -E 'events_total|findings_total'
EOF
}

banner
if pg_up && my_up; then
    log "postgres (${PG_HOST}:${PG_PORT}) and mysql (${MY_HOST}:${MY_PORT}) reachable"
elif pg_up; then
    log "only postgres reachable; mysql steps will be skipped"
elif my_up; then
    log "only mysql reachable; postgres steps will be skipped"
else
    log "no databases reachable - run scripts/setup-dbs.sh first (mysql/postgres steps skipped)"
fi

if pg_up || my_up; then
    sqli_section
    exfil_section
fi
rids_section
outro
