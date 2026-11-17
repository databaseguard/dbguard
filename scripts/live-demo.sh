#!/usr/bin/env bash
# =============================================================================
# live-demo.sh
#
# Usage:  sudo ./scripts/live-demo.sh
# Needs:  root (eBPF), built binaries+objects (make bpf go-build), seeded DBs
#         (scripts/setup-dbs.sh).
# =============================================================================
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"; cd "$ROOT"
[ "$(id -u)" = 0 ] || { echo "run with sudo: sudo ./scripts/live-demo.sh"; exit 2; }

CFG="${DBGUARD_CONFIG:-configs/dbguard.dev.yaml}"
API="http://127.0.0.1:9700"
MET="http://127.0.0.1:9701/metrics"
DBGUARDD=./build/bin/dbguardd
CLI=./build/bin/dbguard-cli
LOG="$(mktemp)"

[ -x "$DBGUARDD" ] || { echo "build first: make bpf go-build"; exit 2; }

# clear any previous instance so we don't get 'address already in use'
pkill -f 'dbguardd -config' 2>/dev/null && sleep 1

# start from a clean audit state so the output shows THIS run's detections, not
# stale events from a previous session.
rm -rf .dbguard-state/audit 2>/dev/null; mkdir -p .dbguard-state/audit

echo "==> starting dbguard (background), config: $CFG"
"$DBGUARDD" -config "$CFG" >"$LOG" 2>&1 &
DPID=$!
cleanup() {
  echo "==> stopping dbguard (pid $DPID)"
  kill -INT "$DPID" 2>/dev/null
  wait "$DPID" 2>/dev/null
  echo "--- daemon log (uprobe attach / ebpf lines) ---"
  grep -iE 'uprobe|ebpf: started|data plane|query auditing|symbol not found|dbgsym' "$LOG" | sed 's/^/    /' || true
  rm -f "$LOG"
}
trap cleanup EXIT

echo -n "==> waiting for API"
for i in $(seq 1 30); do
  if curl -fsS "$API/api/v1/status" >/dev/null 2>&1 || curl -fsS "$API/healthz" >/dev/null 2>&1; then
    echo " - up"; break
  fi
  # if the daemon died early, surface why
  if ! kill -0 "$DPID" 2>/dev/null; then echo; echo "daemon exited early:"; tail -20 "$LOG"; exit 1; fi
  echo -n "."; sleep 0.5
done

# show whether SQL query auditing is active (uprobe attached) up front
if grep -q 'query auditing active' "$LOG"; then
  echo "==> SQL query auditing is ACTIVE (uprobes attached) - expect SQLi + PII from live queries"
elif grep -qi 'symbol not found' "$LOG"; then
  echo "==> NOTE: query-auditing uprobes are INACTIVE (stripped DB binary)."
  echo "    exfil will still fire; for SQLi/PII run:  sudo make dbgsym   then re-run."
fi

sleep 1
echo "==> firing attack simulation"
sudo -u "${SUDO_USER:-root}" ./scripts/demo.sh >/dev/null 2>&1 || ./scripts/demo.sh >/dev/null 2>&1 || true

echo "==> waiting for events to drain"; sleep 3

echo; echo "===================== SECURITY DETECTIONS ====================="
# Security-relevant events first (sqli/pii/exfil/rids/tenant), filtering out the
# high-volume conn.open/close bookkeeping so real findings are visible.
all="$("$CLI" events -n 500 2>/dev/null)"
echo "$all" | grep -iE 'sqli|pii|exfil|rids|tenant|TIME' | head -40 || true
sec=$(echo "$all" | grep -icE 'sqli|pii|exfil|rids|tenant')
conn=$(echo "$all" | grep -icE 'conn\.(open|close)')
echo
echo "  security events: $sec    connection-tracking events: $conn"
[ "$sec" = 0 ] && echo "  (no SQLi/PII/exfil yet - if the daemon log below shows uprobes NOT attached, run: sudo make dbgsym)"
echo
echo "===================== METRICS ======================="
curl -fsS "$MET" 2>/dev/null | grep -E '^(events_total|findings_total)' | sed 's/^/  /' || echo "(metrics unavailable)"
echo
echo "===================== AUDIT TRAIL ===================="
ls .dbguard-state/audit/*.jsonl >/dev/null 2>&1 && {
  echo "  $(cat .dbguard-state/audit/*.jsonl 2>/dev/null | wc -l) records in .dbguard-state/audit/"
  command -v jq >/dev/null && cat .dbguard-state/audit/*.jsonl 2>/dev/null | jq -c 'select(.type)|{type,severity,rule}' 2>/dev/null | sort | uniq -c | sed 's/^/  /' | head
} || echo "  (no audit files yet)"
