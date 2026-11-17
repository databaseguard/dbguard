#!/usr/bin/env bash
# Install DBGuard as a systemd service so it starts on boot, auto-restarts if it
# exits, and is never tied to an interactive shell (ends the stale-daemon cycle).
#
#   sudo ./scripts/install-service.sh            # install + enable + start
#   sudo ./scripts/install-service.sh --config configs/dbguard.yaml   # prod config
#
# Manage it afterward with:
#   sudo systemctl status dbguard
#   sudo systemctl restart dbguard
#   sudo journalctl -u dbguard -f        # live logs
#   sudo systemctl stop dbguard && sudo systemctl disable dbguard   # remove from boot
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG="configs/dbguard.dev.yaml"
[ "${1:-}" = "--config" ] && CONFIG="${2:?--config needs a path}"
UNIT=/etc/systemd/system/dbguard.service

if [ "$(id -u)" -ne 0 ]; then echo "run with sudo"; exit 1; fi
[ -x "$REPO_ROOT/build/bin/dbguardd" ] || { echo "build first: make bpf go-build"; exit 1; }
[ -f "$REPO_ROOT/$CONFIG" ] || { echo "config not found: $REPO_ROOT/$CONFIG"; exit 1; }

echo "== freeing any daemon already holding the ports =="
pkill -9 -f dbguardd 2>/dev/null || true
for p in 9700 9701 6432 6433; do
  pid="$(ss -ltnp 2>/dev/null | grep ":$p " | grep -oP 'pid=\K[0-9]+' | head -1 || true)"
  [ -n "${pid:-}" ] && kill -9 "$pid" 2>/dev/null || true
done
sleep 1

echo "== writing $UNIT (dir=$REPO_ROOT, config=$CONFIG) =="
sed -e "s#__DBGUARD_DIR__#${REPO_ROOT}#g" \
    -e "s#configs/dbguard.dev.yaml#${CONFIG}#g" \
    "$REPO_ROOT/deploy/dbguard.service" > "$UNIT"

echo "== enabling + starting =="
systemctl daemon-reload
systemctl enable dbguard >/dev/null
systemctl restart dbguard
sleep 3

echo
systemctl --no-pager --full status dbguard | head -12 || true
echo
if curl -fsS http://127.0.0.1:9700/api/v1/status >/dev/null 2>&1; then
  echo "OK: dbguard is running under systemd (auto-restart on, starts on boot)."
  echo "    logs:    sudo journalctl -u dbguard -f"
  echo "    restart: sudo systemctl restart dbguard"
else
  echo "WARNING: API not reachable yet - check: sudo journalctl -u dbguard -n 40"
fi
