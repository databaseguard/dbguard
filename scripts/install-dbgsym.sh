#!/usr/bin/env bash
# =============================================================================
set -u
RED=$'\e[31m'; GRN=$'\e[32m'; YEL=$'\e[33m'; RST=$'\e[0m'
ok(){ echo "${GRN}$*${RST}"; }; warn(){ echo "${YEL}$*${RST}"; }; err(){ echo "${RED}$*${RST}"; }

command -v apt-get >/dev/null || {
  warn "non-apt distro - install your postgresql/mysql debuginfo package manually, then restart dbguard."
  exit 0
}
. /etc/os-release 2>/dev/null
CODENAME="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
[ -n "$CODENAME" ] || { err "cannot determine distro codename"; exit 2; }

echo "Enabling ddebs (debug symbol) repository for $CODENAME, including -updates/-security…"
sudo tee /etc/apt/sources.list.d/ddebs.list >/dev/null <<EOF
deb http://ddebs.ubuntu.com ${CODENAME} main restricted universe multiverse
deb http://ddebs.ubuntu.com ${CODENAME}-updates main restricted universe multiverse
deb http://ddebs.ubuntu.com ${CODENAME}-security main restricted universe multiverse
EOF
sudo apt-get install -y ubuntu-dbgsym-keyring >/dev/null 2>&1 || true
sudo apt-get update >/dev/null 2>&1

# Discover the installed DB packages and their EXACT versions, then install the
# dbgsym pinned to that version (apt picks the matching one once -updates is in).
installed_pkgs=""
want=()
if dpkg -s postgresql-16 >/dev/null 2>&1; then
  v="$(dpkg-query -W -f='${Version}' postgresql-16 2>/dev/null)"
  want+=("postgresql-16-dbgsym=$v"); installed_pkgs+=" postgresql-16($v)"
fi
if dpkg -s mysql-server-core-8.0 >/dev/null 2>&1; then
  v="$(dpkg-query -W -f='${Version}' mysql-server-core-8.0 2>/dev/null)"
  want+=("mysql-server-core-8.0-dbgsym=$v"); installed_pkgs+=" mysql-server-core-8.0($v)"
elif dpkg -s mariadb-server-core >/dev/null 2>&1; then
  v="$(dpkg-query -W -f='${Version}' mariadb-server-core 2>/dev/null)"
  want+=("mariadb-server-core-dbgsym=$v"); installed_pkgs+=" mariadb-server-core($v)"
fi
echo "Installed DB packages:${installed_pkgs:- none found}"

rc=0
for p in "${want[@]}"; do
  echo "Installing $p …"
  if ! sudo apt-get install -y "$p" 2>/tmp/dbgsym.err; then
    # exact-version pin may be unavailable; retry unpinned (picks newest ddeb)
    base="${p%%=*}"
    warn "  exact version not found; trying $base (newest available)…"
    sudo apt-get install -y "$base" 2>/tmp/dbgsym.err || { err "  failed: $(tail -1 /tmp/dbgsym.err)"; rc=1; }
  fi
done

# ---- VERIFY the symbol is actually resolvable now (the honest check) ---------
echo; echo "Verifying uprobe symbols are resolvable…"
has_sym() { # $1 elf-file  $2 symbol  -> 0 if present
  nm "$1" 2>/dev/null | grep -qwE "$2" || readelf -sW "$1" 2>/dev/null | grep -qwE "$2"
}
verify_sym() { # $1 binary  $2 symbol  -> 0 resolvable (in binary OR its debug file)
  local bin="$1" sym="$2" bid dbg abs
  [ -e "$bin" ] || return 2
  has_sym "$bin" "$sym" && return 0            # symbol in the binary itself
  # separate debug file via build-id (what dbgsym installs)
  bid="$(file "$bin" 2>/dev/null | grep -oE 'BuildID\[sha1\]=[0-9a-f]+' | cut -d= -f2)"
  if [ -n "$bid" ]; then
    dbg="/usr/lib/debug/.build-id/${bid:0:2}/${bid:2}.debug"
    [ -f "$dbg" ] && has_sym "$dbg" "$sym" && return 0
  fi
  # fallback: debuglink path /usr/lib/debug/<abs>.debug (and without .debug)
  abs="$(readlink -f "$bin")"
  for dbg in "/usr/lib/debug${abs}.debug" "/usr/lib/debug${abs}"; do
    [ -f "$dbg" ] && has_sym "$dbg" "$sym" && return 0
  done
  return 1
}

pg_bin="$(command -v postgres || echo /usr/lib/postgresql/16/bin/postgres)"
my_bin="$(command -v mysqld || echo /usr/sbin/mysqld)"
any_ok=0
if [ -x "$pg_bin" ]; then
  if verify_sym "$pg_bin" exec_simple_query; then ok "  postgres: exec_simple_query resolvable ✔"; any_ok=1
  else err "  postgres: exec_simple_query NOT resolvable; dbgsym missing/mismatched"; rc=1; fi
fi
if [ -x "$my_bin" ]; then
  if verify_sym "$my_bin" _Z16dispatch_command19enum_server_commandP3THDPcjbb || verify_sym "$my_bin" dispatch_command; then
    ok "  mysql: dispatch_command resolvable ✔"; any_ok=1
  else warn "  mysql: dispatch_command not resolvable (mysql symbol is C++-mangled; uprobe may still match via debug file)"; fi
fi

echo
if [ "$any_ok" = 1 ]; then
  ok "SUCCESS - restart dbguard; the log should now show:"
  ok "  \"ebpf: uprobe attached (SQL query auditing active)\""
  echo "  sudo ./build/bin/dbguardd -config configs/dbguard.dev.yaml"
else
  err "Debug symbols are still not resolvable."
  echo "This usually means the ddeb for your exact DB version isn't published yet."
  echo "Alternatives:"
  echo "  • Use dbguard's wire-capture mode (no symbols needed) - see docs/quickstart.md"
  echo "  • Check availability:  apt-cache madison postgresql-16-dbgsym"
fi
exit "$rc"
