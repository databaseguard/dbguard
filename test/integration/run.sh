#!/usr/bin/env bash
# DBGuard integration test.
#
# Boots postgres + mysql + dbguard under docker compose, runs the attack
# simulation inside the attacker container, then greps the agent's audit
# JSONL for the expected detection ids. Exits non-zero when a detection is
# missing.
#
# Usage:
#   test/integration/run.sh           # full run
#   test/integration/run.sh --down    # tear the stack down afterwards
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
COMPOSE="docker compose -f ${REPO_ROOT}/deploy/docker-compose.yml"
TEARDOWN=0
[ "${1:-}" = "--down" ] && TEARDOWN=1

log() { echo "[integration] $*"; }

cleanup() {
    if [ "$TEARDOWN" -eq 1 ]; then
        log "tearing down compose stack"
        $COMPOSE down -v --remove-orphans >/dev/null 2>&1 || true
    fi
}
trap cleanup EXIT

log "building and starting stack (postgres, mysql, dbguard)"
$COMPOSE up -d --build postgres mysql dbguard

wait_healthy() {  # $1 service name, $2 max seconds
    local svc="$1" max="$2" i=0 status
    while [ "$i" -lt "$max" ]; do
        status="$($COMPOSE ps --format json "$svc" 2>/dev/null | sed -n 's/.*"Health":"\([a-z]*\)".*/\1/p' || true)"
        [ "$status" = "healthy" ] && return 0
        sleep 2; i=$((i + 2))
    done
    log "WARNING: $svc not healthy after ${max}s, continuing"
}
wait_healthy postgres 90
wait_healthy mysql 120
log "databases healthy; giving the agent 5s to settle"
sleep 5

log "running attack simulation in the attacker container"
$COMPOSE run --rm attacker sh -c \
    "apk add --no-cache -q postgresql-client mysql-client && sh /sim/attack_sim.sh"

log "fetching audit trail from the dbguard container"
$COMPOSE exec -T dbguard sh -c \
    'cat /var/lib/dbguard/audit/*.jsonl 2>/dev/null || true' \
    > /tmp/dbguard_audit.jsonl || true
# Fallback: stdout logs also carry event lines.
$COMPOSE logs dbguard >> /tmp/dbguard_audit.jsonl 2>/dev/null || true

FAILED=0
check() {  # $1 detection id expected in the audit trail
    if grep -qF "$1" /tmp/dbguard_audit.jsonl; then
        log "PASS: found detection '$1'"
    else
        log "FAIL: detection '$1' missing from audit trail"
        FAILED=1
    fi
}

check '"type":"sqli.attempt"'
check '"type":"exfil.burst"'
check '"rule_id":"sqli.tautology"'
check 'query.audit'

if [ "$FAILED" -eq 0 ]; then
    log "ALL DETECTIONS PRESENT - integration test PASSED"
else
    log "missing detections - integration test FAILED"
    log "debug: docker compose -f deploy/docker-compose.yml logs dbguard | grep sqli"
fi
exit "$FAILED"
