#!/usr/bin/env bash
# DBGuard source sanity checks (used locally and as the CI gate).
# Runs, in order: gofmt, go vet, make bpf (if clang present), go test and
# config/policy validation via dbguard-cli. Exits non-zero on any failure.
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"
FAILED=0

note() { echo "[verify] $*"; }

echo "== [1/5] gofmt =="
if command -v gofmt >/dev/null 2>&1; then
    UNFORMATTED="$(gofmt -l . 2>/dev/null | grep -v '^build/' || true)"
    if [ -n "$UNFORMATTED" ]; then
        echo "unformatted files:"
        echo "$UNFORMATTED"
        FAILED=1
    else
        note "gofmt clean"
    fi
else
    note "SKIP: gofmt not found"
fi

echo "== [2/5] go vet =="
if command -v go >/dev/null 2>&1; then
    if ! go vet ./...; then FAILED=1; fi
else
    note "SKIP: go toolchain not found"
fi

echo "== [3/5] make bpf =="
if command -v clang >/dev/null 2>&1; then
    if ! make bpf; then FAILED=1; fi
else
    note "SKIP: clang not found (eBPF objects not built)"
fi

echo "== [4/5] go test =="
if command -v go >/dev/null 2>&1; then
    if ! go test ./internal/...; then FAILED=1; fi
else
    note "SKIP: go toolchain not found"
fi

echo "== [5/5] config/policy validation =="
CLI=""
for candidate in build/bin/dbguard-cli dbguard-cli; do
    if [ -x "$candidate" ] || command -v "$candidate" >/dev/null 2>&1; then
        CLI="$candidate"; break
    fi
done
if [ -n "$CLI" ]; then
    if ! "$CLI" validate-config -c configs/dbguard.yaml; then FAILED=1; fi
    if ! "$CLI" validate-policy -d configs/policies; then FAILED=1; fi
else
    note "SKIP: dbguard-cli not built yet"
fi

echo
if [ "$FAILED" -eq 0 ]; then
    echo "[verify] ALL CHECKS PASSED"
else
    echo "[verify] FAILURES DETECTED (see output above)"
fi
exit "$FAILED"
