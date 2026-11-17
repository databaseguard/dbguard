#!/usr/bin/env bash

# Usage:
#   scripts/setup-dbs.sh               # native APT install + seed
#   scripts/setup-dbs.sh --docker      # run DBs as Docker containers + seed
#   scripts/setup-dbs.sh --seed-only   # skip install, (re)create data only
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

PG_PORT="${PG_PORT:-5432}"
MYSQL_PORT="${MYSQL_PORT:-3306}"
PG_DB="dbguard_test";   PG_USER="dbguard";   PG_PASS="dbguard";   PG_RO="dbguard_ro"
MY_DB="dbguard_test";   MY_USER="dbguard";   MY_PASS="dbguard";   MY_RO="dbguard_ro"
SQLITE_DB="${SQLITE_DB:-/tmp/dbguard_test.db}"

MODE="native"
SEED_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --docker)    MODE="docker" ;;
        --seed-only) SEED_ONLY=1 ;;
        -h|--help)
            sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown flag: $arg (see --help)"; exit 2 ;;
    esac
done

if [ "$(id -u)" -eq 0 ]; then SUDO=""; else SUDO="sudo"; fi

log()  { echo "[setup-dbs] $*"; }
warn() { echo "[setup-dbs] WARNING: $*" >&2; }

# --------------------------------------------------------------- install ---
provision_native() {
    # Skip apt entirely when the databases are already installed - avoids
    # aborting (set -e) on an unrelated third-party repo error during
    # `apt-get update`, and makes re-runs fast. Seeding still proceeds.
    if command -v psql >/dev/null 2>&1 && \
       { command -v mysql >/dev/null 2>&1 || command -v mariadb >/dev/null 2>&1; }; then
        log "postgresql and mysql/mariadb already installed - skipping apt"
        $SUDO systemctl enable --now postgresql 2>/dev/null || $SUDO service postgresql start 2>/dev/null || true
        $SUDO systemctl enable --now mysql 2>/dev/null || $SUDO service mysql start 2>/dev/null || true
        return 0
    fi
    log "installing postgresql, mysql-server, sqlite3 via apt"
    $SUDO apt-get update || warn "apt-get update failed (continuing; DBs may already be installed)"
    DEBIAN_FRONTEND=noninteractive $SUDO apt-get install -y \
        postgresql postgresql-contrib mysql-server sqlite3 || \
        warn "apt-get install reported errors (continuing; will try to seed existing DBs)"
    # systemd first, SysV fallback for minimal containers.
    $SUDO systemctl enable --now postgresql 2>/dev/null || $SUDO service postgresql start
    $SUDO systemctl enable --now mysql 2>/dev/null      || $SUDO service mysql start
    cat <<'EOF'
[setup-dbs] NOTE (security): on Debian/Ubuntu, MySQL root uses auth_socket,
[setup-dbs] so root access is only via `sudo mysql`. We create dedicated
[setup-dbs] dbguard/dbguard_ro accounts below; do not run services as root.
EOF
}

provision_docker() {
    command -v docker >/dev/null || { echo "ERROR: docker not found"; exit 1; }
    if ! docker ps --format '{{.Names}}' | grep -qx dbguard-postgres; then
        docker rm -f dbguard-postgres >/dev/null 2>&1 || true
        log "starting postgres:16-alpine on :${PG_PORT}"
        docker run -d --name dbguard-postgres -p "${PG_PORT}:5432" \
            -e POSTGRES_PASSWORD=dbguard -e POSTGRES_DB=dbguard_test \
            postgres:16-alpine >/dev/null
    fi
    if ! docker ps --format '{{.Names}}' | grep -qx dbguard-mysql; then
        docker rm -f dbguard-mysql >/dev/null 2>&1 || true
        log "starting mysql:8.0 on :${MYSQL_PORT}"
        docker run -d --name dbguard-mysql -p "${MYSQL_PORT}:3306" \
            -e MYSQL_ROOT_PASSWORD=dbguard -e MYSQL_DATABASE=dbguard_test \
            mysql:8.0 >/dev/null
    fi
    log "waiting for postgres health (pg_isready)"
    for _ in $(seq 1 60); do
        docker exec dbguard-postgres pg_isready -U postgres -d dbguard_test >/dev/null 2>&1 && break
        sleep 1
    done
    log "waiting for mysql health (mysqladmin ping)"
    for _ in $(seq 1 90); do
        docker exec dbguard-mysql mysqladmin ping -uroot -pdbguard --silent >/dev/null 2>&1 && break
        sleep 1
    done
}

# ----------------------------------------------------------------- users ---
pg_superuser() {  # psql as the postgres OS/superuser, args passed through
    if [ "$MODE" = "docker" ]; then
        docker exec dbguard-postgres psql -U postgres "$@"
    elif [ -n "$SUDO" ]; then
        $SUDO -u postgres psql "$@"           # invoked as a normal user
    else
        runuser -u postgres -- psql "$@"      # already root (e.g. sudo ./setup-dbs.sh)
    fi
}

create_pg_users() {
    log "creating PostgreSQL users ${PG_USER} / ${PG_RO} and database ${PG_DB}"
    pg_superuser -tAc "SELECT 1 FROM pg_roles WHERE rolname='${PG_USER}'" | grep -q 1 || \
        pg_superuser -c "CREATE USER ${PG_USER} WITH PASSWORD '${PG_PASS}';"
    pg_superuser -tAc "SELECT 1 FROM pg_roles WHERE rolname='${PG_RO}'" | grep -q 1 || \
        pg_superuser -c "CREATE USER ${PG_RO} WITH PASSWORD '${PG_PASS}';"
    pg_superuser -tAc "SELECT 1 FROM pg_database WHERE datname='${PG_DB}'" | grep -q 1 || \
        pg_superuser -c "CREATE DATABASE ${PG_DB} OWNER ${PG_USER};"
}

mysql_root_stdin() {  # feed SQL on stdin as root
    if [ "$MODE" = "docker" ]; then docker exec -i dbguard-mysql mysql -uroot -pdbguard 2>/dev/null
    else $SUDO mysql 2>/dev/null; fi
}

create_mysql_users() {
    log "creating MySQL users ${MY_USER} / ${MY_RO} and database ${MY_DB}"
    local native plain
    # Debian/Ubuntu ships mysql_native_password; if the plugin is disabled
    # (MySQL 8.4+), fall back to the default authentication plugin.
    native="CREATE USER IF NOT EXISTS 'dbguard'@'localhost' IDENTIFIED WITH mysql_native_password BY 'dbguard';
            CREATE USER IF NOT EXISTS 'dbguard_ro'@'localhost' IDENTIFIED WITH mysql_native_password BY 'dbguard';
            CREATE USER IF NOT EXISTS 'dbguard'@'127.0.0.1' IDENTIFIED WITH mysql_native_password BY 'dbguard';
            CREATE USER IF NOT EXISTS 'dbguard_ro'@'127.0.0.1' IDENTIFIED WITH mysql_native_password BY 'dbguard';"
    plain="CREATE USER IF NOT EXISTS 'dbguard'@'localhost' IDENTIFIED BY 'dbguard';
           CREATE USER IF NOT EXISTS 'dbguard_ro'@'localhost' IDENTIFIED BY 'dbguard';
           CREATE USER IF NOT EXISTS 'dbguard'@'127.0.0.1' IDENTIFIED BY 'dbguard';
           CREATE USER IF NOT EXISTS 'dbguard_ro'@'127.0.0.1' IDENTIFIED BY 'dbguard';"
    if ! printf '%s' "$native" | mysql_root_stdin; then
        warn "mysql_native_password unavailable, using default plugin"
        printf '%s' "$plain" | mysql_root_stdin
    fi
    printf "CREATE DATABASE IF NOT EXISTS ${MY_DB};
            GRANT ALL PRIVILEGES ON ${MY_DB}.* TO 'dbguard'@'localhost';
            GRANT ALL PRIVILEGES ON ${MY_DB}.* TO 'dbguard'@'127.0.0.1';
            GRANT SELECT ON ${MY_DB}.* TO 'dbguard_ro'@'localhost';
            GRANT SELECT ON ${MY_DB}.* TO 'dbguard_ro'@'127.0.0.1';
            FLUSH PRIVILEGES;" | mysql_root_stdin
    # Docker containers are reached over TCP from the host with host=%.
    if [ "$MODE" = "docker" ]; then
        printf "CREATE USER IF NOT EXISTS 'dbguard'@'%%' IDENTIFIED BY 'dbguard';
                CREATE USER IF NOT EXISTS 'dbguard_ro'@'%%' IDENTIFIED BY 'dbguard';
                GRANT ALL PRIVILEGES ON ${MY_DB}.* TO 'dbguard'@'%%';
                GRANT SELECT ON ${MY_DB}.* TO 'dbguard_ro'@'%%';
                FLUSH PRIVILEGES;" | mysql_root_stdin
    fi
}

# ------------------------------------------------------------------ data ---
ddl_pg() {
    cat <<'SQL'
DROP TABLE IF EXISTS orders, employees, customers CASCADE;
CREATE TABLE customers (id SERIAL PRIMARY KEY, full_name TEXT, email TEXT, phone TEXT, ssn TEXT, credit_card TEXT, salary NUMERIC);
CREATE TABLE employees (id SERIAL PRIMARY KEY, name TEXT, email TEXT, department TEXT, salary NUMERIC);
CREATE TABLE orders (id SERIAL PRIMARY KEY, customer_id INT, item TEXT, amount NUMERIC, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
SQL
}

ddl_mysql() {
    cat <<'SQL'
DROP TABLE IF EXISTS orders, employees, customers;
CREATE TABLE customers (id INT AUTO_INCREMENT PRIMARY KEY, full_name TEXT, email TEXT, phone TEXT, ssn TEXT, credit_card TEXT, salary NUMERIC);
CREATE TABLE employees (id INT AUTO_INCREMENT PRIMARY KEY, name TEXT, email TEXT, department TEXT, salary NUMERIC);
CREATE TABLE orders (id INT AUTO_INCREMENT PRIMARY KEY, customer_id INT, item TEXT, amount NUMERIC, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);
SQL
}

ddl_sqlite() {
    cat <<'SQL'
CREATE TABLE IF NOT EXISTS customers (id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT, email TEXT, phone TEXT, ssn TEXT, credit_card TEXT, salary NUMERIC);
CREATE TABLE IF NOT EXISTS employees (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT, department TEXT, salary NUMERIC);
CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, customer_id INT, item TEXT, amount NUMERIC, created_at TEXT DEFAULT CURRENT_TIMESTAMP);
SQL
}

gen_seed_sql() {
    # Dialect-neutral INSERTs: 50 rows per table of synthetic data.
    # Cards are Luhn-valid test numbers; SSNs are patterned 3-2-4 groups.
    local cards=(4111111111111111 5500000000000004 340000000000009 6011111111111117)
    local names=(alice bob carol dave eve frank grace heidi ivan judy mallory nils olivia peggy trent)
    local depts=(engineering finance hr sales support)
    local items=(laptop monitor keyboard desk chair phone headset dock printer router)
    local i name card ssn email phone salary dept item amount
    echo "INSERT INTO customers (full_name,email,phone,ssn,credit_card,salary) VALUES"
    for i in $(seq 1 50); do
        name="${names[$(( (i-1) % ${#names[@]} ))]}"
        card="${cards[$(( (i-1) % ${#cards[@]} ))]}"
        ssn=$(printf '%03d-%02d-%04d' "$((100+i))" "$((10 + i % 80))" "$((1000+i))")
        email="${name}.${i}@example.com"
        phone="+1-555-$(printf '%04d' "$((1000+i))")"
        salary=$((45000 + i * 1379))
        printf "  ('%s %d','%s','%s','%s','%s',%d)%s\n" "$name" "$i" "$email" "$phone" "$ssn" "$card" "$salary" "$([ "$i" -lt 50 ] && echo ',' || echo ';')"
    done
    echo "INSERT INTO employees (name,email,department,salary) VALUES"
    for i in $(seq 1 50); do
        name="${names[$(( (i-1) % ${#names[@]} ))]}"
        dept="${depts[$(( (i-1) % ${#depts[@]} ))]}"
        email="${name}.emp.${i}@example.com"
        salary=$((40000 + i * 1123))
        printf "  ('%s emp%d','%s','%s',%d)%s\n" "$name" "$i" "$email" "$dept" "$salary" "$([ "$i" -lt 50 ] && echo ',' || echo ';')"
    done
    echo "INSERT INTO orders (customer_id,item,amount) VALUES"
    for i in $(seq 1 50); do
        item="${items[$(( (i-1) % ${#items[@]} ))]}"
        amount=$(printf '%.2f' "$(echo "$((9000 + i * 313))" | awk '{printf "%.2f", $1/100}')")
        printf "  (%d,'%s',%s)%s\n" "$(( (i-1) % 50 + 1 ))" "$item" "$amount" "$([ "$i" -lt 50 ] && echo ',' || echo ';')"
    done
}

pg_client() { PGPASSWORD="${PG_PASS}" psql -h 127.0.0.1 -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" -v ON_ERROR_STOP=1 "$@"; }
my_client() { mysql -h 127.0.0.1 -P "${MYSQL_PORT}" -u "${MY_USER}" -p"${MY_PASS}" "${MY_DB}" "$@"; }

seed_pg() {
    local count hascc
    count="$(pg_client -tAc 'SELECT count(*) FROM customers' 2>/dev/null || echo 0)"
    count="$(echo "$count" | tr -d '[:space:]')"; count="${count:-0}"
    # Re-seed when the table is empty OR the full schema (credit_card column) is
    # missing - guards against a partial/hand-made customers table.
    hascc="$(pg_client -tAc "SELECT 1 FROM information_schema.columns WHERE table_name='customers' AND column_name='credit_card'" 2>/dev/null | tr -d '[:space:]')"
    if [ "$count" -eq 0 ] || [ "$hascc" != "1" ]; then
        log "seeding PostgreSQL (${PG_DB})"
        # DDL + seed run as the superuser: on PostgreSQL 15+ a plain role cannot
        # CREATE in schema public or drop tables it does not own. Grant the app
        # users afterward.
        {
            ddl_pg
            gen_seed_sql
            echo "ALTER TABLE customers OWNER TO ${PG_USER};"
            echo "ALTER TABLE employees OWNER TO ${PG_USER};"
            echo "ALTER TABLE orders OWNER TO ${PG_USER};"
            echo "GRANT ALL ON ALL TABLES IN SCHEMA public TO ${PG_USER};"
            echo "GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO ${PG_USER};"
            # Optional read-only role: grant only if it exists (don't abort).
            echo "DO \$\$ BEGIN IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='${PG_RO}') THEN EXECUTE 'GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${PG_RO}'; END IF; END \$\$;"
        } | pg_superuser -d "${PG_DB}" -v ON_ERROR_STOP=1
    else
        log "PostgreSQL already seeded (customers=$count)"
    fi
    pg_superuser -d "${PG_DB}" -c "GRANT SELECT ON ALL TABLES IN SCHEMA public TO ${PG_RO};" >/dev/null 2>&1 || true
}

seed_mysql() {
    local count hascc
    count="$(my_client -NBe 'SELECT count(*) FROM customers' 2>/dev/null || echo 0)"
    count="$(echo "$count" | tr -d '[:space:]')"; count="${count:-0}"
    hascc="$(my_client -NBe "SELECT 1 FROM information_schema.columns WHERE table_schema='${MY_DB}' AND table_name='customers' AND column_name='credit_card'" 2>/dev/null | tr -d '[:space:]')"
    if [ "$count" -eq 0 ] || [ "$hascc" != "1" ]; then
        log "seeding MySQL (${MY_DB})"
        { ddl_mysql; gen_seed_sql; } | my_client
    else
        log "MySQL already seeded (customers=$count)"
    fi
}

seed_sqlite() {
    command -v sqlite3 >/dev/null || { warn "sqlite3 not installed; skipping"; return 0; }
    local count
    count="$(sqlite3 "${SQLITE_DB}" 'SELECT count(*) FROM customers' 2>/dev/null || echo 0)"
    count="${count:-0}"
    if [ "$count" -eq 0 ]; then
        log "seeding SQLite (${SQLITE_DB})"
        { ddl_sqlite; gen_seed_sql; } | sqlite3 "${SQLITE_DB}"
    else
        log "SQLite already seeded (customers=$count)"
    fi
}

# ---------------------------------------------------------------- verify ---
verify() {
    log "verification"
    local pg_count my_count sq_count
    pg_count="n/a"; my_count="n/a"; sq_count="n/a"
    if command -v pg_isready >/dev/null && pg_isready -h 127.0.0.1 -p "${PG_PORT}" -q 2>/dev/null; then
        pg_count="$(PGPASSWORD="${PG_PASS}" psql -h 127.0.0.1 -p "${PG_PORT}" -U "${PG_USER}" -d "${PG_DB}" -tAc 'SELECT count(*) FROM customers' 2>/dev/null || echo ERR)"
    else
        warn "postgres not reachable on 127.0.0.1:${PG_PORT}"
    fi
    if mysqladmin ping -h 127.0.0.1 -P "${MYSQL_PORT}" -u "${MY_USER}" -p"${MY_PASS}" --silent 2>/dev/null; then
        my_count="$(my_client -NBe 'SELECT count(*) FROM customers' 2>/dev/null || echo ERR)"
    else
        warn "mysql not reachable on 127.0.0.1:${MYSQL_PORT}"
    fi
    if command -v sqlite3 >/dev/null; then
        sq_count="$(sqlite3 "${SQLITE_DB}" 'SELECT count(*) FROM customers' 2>/dev/null || echo ERR)"
        echo "sqlite3 $(sqlite3 --version | awk '{print $1, $2}')"
    fi
    echo
    echo "+------------------+----------------------+-------------------------+"
    printf '| %-16s| %-20s| %-23s|\n' "ENGINE" "ENDPOINT" "CREDENTIALS"
    echo "+------------------+----------------------+-------------------------+"
    printf '| %-16s| %-20s| %-23s|\n' "postgres ($pg_count rows)" "127.0.0.1:${PG_PORT}" "${PG_USER}/${PG_PASS} ro:${PG_RO}"
    printf '| %-16s| %-20s| %-23s|\n' "mysql ($my_count rows)" "127.0.0.1:${MYSQL_PORT}" "${MY_USER}/${MY_PASS} ro:${MY_RO}"
    printf '| %-16s| %-20s| %-23s|\n' "sqlite ($sq_count rows)" "${SQLITE_DB}" "file only"
    echo "+------------------+----------------------+-------------------------+"
    cat <<'EOF'

Next steps:
  1. start DBGuard:      sudo ./build/bin/dbguardd -config configs/dbguard.yaml
  2. run the attack sim: scripts/demo.sh
  3. inspect findings:   ./build/bin/dbguard-cli events -n 20
EOF
}

# ------------------------------------------------------------------ main ---
if [ "$SEED_ONLY" -eq 0 ]; then
    if [ "$MODE" = "docker" ]; then provision_docker; else provision_native; fi
    create_pg_users
    create_mysql_users
else
    log "--seed-only: skipping installation, using existing databases"
fi
seed_pg
seed_mysql
seed_sqlite
verify
