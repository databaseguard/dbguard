#!/bin/sh
# DBGuard attack simulation - runs INSIDE the attacker container.
# Requires: postgres + mysql reachable via the compose network (service
# names postgres/mysql). Prints PASS/FAIL per attempt and exits non-zero
# when the environment itself is broken (connection failures).
#
# The queries are hostile-shaped but harmless: the stacked-query target is
# a table that never exists and the bulk dump discards all output.
set -u

PG="psql -h postgres -p 5432 -U dbguard -d dbguard_test"
export PGPASSWORD=dbguard
MY="mysql -h mysql -P 3306 -u dbguard -pdbguard dbguard_test"

PASS=0
FAIL=0
ERRORS=0

report() {  # $1 name, $2 rc
    case "$2" in
        0) echo "PASS: $1"; PASS=$((PASS + 1)) ;;
        *) echo "FAIL: $1 (exit $2)"; FAIL=$((FAIL + 1)) ;;
    esac
}

attempt() {  # $1 name, $2 command (executed, output discarded)
    if $2 >/dev/null 2>&1; then
        report "$1" 0
    else
        report "$1" 1
    fi
}

connectivity() {
    if ! $PG -c "SELECT 1" >/dev/null 2>&1; then
        echo "ERROR: postgres unreachable from attacker container"
        ERRORS=$((ERRORS + 1))
    fi
    if ! $MY -e "SELECT 1" >/dev/null 2>&1; then
        echo "ERROR: mysql unreachable from attacker container"
        ERRORS=$((ERRORS + 1))
    fi
    [ "$ERRORS" -eq 0 ]
}

echo "== attack_sim: SQL injection =="
attempt "pg tautology OR 1=1" \
    "$PG -c \"SELECT id, email FROM customers WHERE full_name = '' OR 1=1 --\""
attempt "pg UNION SELECT credit_card" \
    "$PG -c \"SELECT id, full_name FROM customers WHERE id = 1 UNION SELECT credit_card, ssn FROM customers\""
attempt "pg time-based pg_sleep(2)" \
    "$PG -c 'SELECT pg_sleep(2)'"
attempt "mysql tautology OR 1=1" \
    "$MY -e \"SELECT id, email FROM customers WHERE full_name = '' OR 1=1 #\""
attempt "mysql UNION SELECT credit_card" \
    "$MY -e \"SELECT id, name FROM customers WHERE id = 1 UNION SELECT credit_card, ssn FROM customers\""
attempt "mysql time-based SLEEP(3)" \
    "$MY -e 'SELECT SLEEP(3)'"

echo "== attack_sim: stacked destructive statement (harmless target) =="
attempt "pg stacked DROP TABLE _dbguard_sim_noop" \
    "$PG -c 'SELECT 1; DROP TABLE IF EXISTS _dbguard_sim_noop'"
attempt "mysql stacked DROP TABLE _dbguard_sim_noop" \
    "$MY -e 'SELECT 1; DROP TABLE IF EXISTS _dbguard_sim_noop'"

echo "== attack_sim: bulk dump (10 unbounded reads each) =="
i=0
while [ $i -lt 10 ]; do
    $PG -c "SELECT * FROM customers" >/dev/null 2>&1 || true
    $MY -e "SELECT * FROM employees" >/dev/null 2>&1 || true
    i=$((i + 1))
done
attempt "pg bulk dump loop" "$PG -c 'SELECT * FROM customers'"
attempt "mysql bulk dump loop" "$MY -e 'SELECT * FROM employees'"

echo "== attack_sim: summary =="
echo "PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -eq 0 ]; then
    echo "all attempts executed; check dbguard audit for sqli.attempt/exfil.burst"
    exit 0
fi
echo "some attempts failed to execute - check client installation"
exit 1
