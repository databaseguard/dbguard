#!/usr/bin/env bash
# Validate DBGuard policies, install them into /etc/dbguard/policies and
# trigger a hot reload via the admin API.
#
# Env:
#   DBGUARD_API_TOKEN   bearer token matching api.token in dbguard.yaml
#   DBGUARD_API         API base URL (default http://127.0.0.1:9700)
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
POLICY_SRC="${1:-${REPO_ROOT}/configs/policies}"
POLICY_DST="${POLICY_DST:-/etc/dbguard/policies}"
API="${DBGUARD_API:-http://127.0.0.1:9700}"
TOKEN="${DBGUARD_API_TOKEN:-}"

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

# 1. Locate the CLI (repo build first, then PATH).
CLI=""
for candidate in "${REPO_ROOT}/build/bin/dbguard-cli" dbguard-cli; do
    if command -v "$candidate" >/dev/null 2>&1; then CLI="$candidate"; break; fi
done
if [ -z "$CLI" ]; then
    echo "ERROR: dbguard-cli not found (run make go-build or install it)" >&2
    exit 1
fi

# 2. Validate before touching the live directory.
echo "== validating policies in ${POLICY_SRC} =="
"$CLI" validate-policy "$POLICY_SRC"

# 3. Install into the configured policy directory.
echo "== installing policies into ${POLICY_DST} =="
$SUDO mkdir -p "$POLICY_DST"
for f in "$POLICY_SRC"/*.yaml; do
    $SUDO install -m 0644 "$f" "$POLICY_DST/"
    echo "  installed: $(basename "$f")"
done

# 4. Hot reload through the admin API (empty token = loopback without auth).
echo "== reloading via ${API} =="
if curl -fsS -X POST "${API}/api/v1/policies/reload" \
        -H "Authorization: Bearer ${TOKEN}" \
        -H "Content-Type: application/json" \
        -d '{}'; then
    echo "reload accepted"
else
    echo "WARNING: reload request failed (daemon down or token mismatch);" >&2
    echo "         policies are installed and will load on next start." >&2
    exit 1
fi
