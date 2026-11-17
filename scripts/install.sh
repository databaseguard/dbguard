#!/usr/bin/env bash
# DBGuard installer for Ubuntu/Debian hosts.
#
# Installs the build toolchain (clang/llvm/libbpf/Go), builds the eBPF
# objects and the Go binaries, and optionally provisions local test
# databases via scripts/setup-dbs.sh.
#
# Usage:
#   scripts/install.sh              # toolchain + build
#   scripts/install.sh --with-dbs   # also install/seed PostgreSQL+MySQL+SQLite
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WITH_DBS=0

usage() {
    echo "usage: scripts/install.sh [--with-dbs]"
    echo "  --with-dbs   also run scripts/setup-dbs.sh (local PostgreSQL/MySQL/SQLite)"
}

for arg in "$@"; do
    case "$arg" in
        --with-dbs) WITH_DBS=1 ;;
        -h|--help)  usage; exit 0 ;;
        *)          usage; exit 2 ;;
    esac
done

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

echo "== [1/5] installing build dependencies (apt) =="
$SUDO apt-get update
DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y \
    clang llvm libelf-dev "linux-headers-$(uname -r)" libbpf-dev \
    golang-go git curl

echo "== [2/5] verifying toolchain versions =="
command -v clang >/dev/null || { echo "ERROR: clang missing after install"; exit 1; }
command -v go    >/dev/null || { echo "ERROR: go missing after install"; exit 1; }
echo "clang:      $(clang --version | head -n1)"
if command -v llvm-strip >/dev/null; then
    echo "llvm-strip: $(llvm-strip --version | head -n1)"
fi
echo "go:         $(go version)"

# Go >= 1.22 is required (go.mod says go 1.22).
GO_RAW="$(go version | awk '{print $3}')"
GO_VER="${GO_RAW#go}"
GO_MAJOR="${GO_VER%%.*}"
GO_MINOR="${GO_VER#*.}"; GO_MINOR="${GO_MINOR%%.*}"
if [ "$GO_MAJOR" -lt 1 ] || { [ "$GO_MAJOR" -eq 1 ] && [ "$GO_MINOR" -lt 22 ]; }; then
    echo "ERROR: Go 1.22+ required, found $GO_RAW"
    exit 1
fi

echo "== [3/5] resolving module dependencies =="
cd "$REPO_ROOT"
go mod tidy

echo "== [4/5] building eBPF objects and Go binaries =="
make

echo "== [5/5] artifacts =="
ls -l build/bin build/bpf

if [ "$WITH_DBS" -eq 1 ]; then
    echo "== provisioning test databases =="
    bash "$REPO_ROOT/scripts/setup-dbs.sh"
fi

cat <<'EOF'

Done. Next steps:
  sudo ./build/bin/dbguardd -config configs/dbguard.yaml   # run the agent (root: BPF)
  ./build/bin/dbguard-cli events -n 10                     # tail observed events
  scripts/demo.sh                                          # fire a scripted attack
EOF
