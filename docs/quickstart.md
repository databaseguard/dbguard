# DBGuard quickstart (5 minutes)

Observes and protects local PostgreSQL/MySQL from the kernel via eBPF.

## Prerequisites

- Linux 5.8+ (BPF ring buffers), root access
- clang >= 11 with the BPF target, llvm-strip
- Go 1.22+
- One of Ubuntu 22.04/24.04 or Debian 12 (or any distro with the packages below)

Check the BPF target quickly:

    clang --version | head -n1

## 1. Build

    git clone https://github.com/databaseguard/dbguard && cd dbguard
    make                # = make bpf + make go-build

Artifacts: `build/bpf/*.bpf.o` (kernel programs), `build/bin/dbguardd`
(daemon), `build/bin/dbguard-cli` (CLI).

## 2. Provision test databases (skip if you already have them)

    sudo scripts/setup-dbs.sh

`dbguard/dbguard` (read-write) and `dbguard_ro/dbguard` (read-only),
database `dbguard_test`, and seeds 50 synthetic rows per table
(Luhn-valid fake cards, patterned SSNs, `@example.com` mail).

## 3. Start the agent (root is required for BPF)

    sudo ./build/bin/dbguardd -config configs/dbguard.yaml

On startup it loads `build/bpf/*.bpf.o` (copy them to
`/var/lib/dbguard/bpf` or set `ebpf.object_dir`), attaches cgroup_skb and
uprobe hooks, loads `configs/policies/*.yaml` and starts the API on
`127.0.0.1:9700` and metrics on `127.0.0.1:9701`.

## 4. Fire one test attack

In another terminal (plain SQL, no tools needed):

    PGPASSWORD=dbguard psql -h 127.0.0.1 -U dbguard -d dbguard_test \
        -c "SELECT id, email FROM customers WHERE full_name = '' OR 1=1 --"

## 5. See the detection

    ./build/bin/dbguard-cli events -n 10

Expected output (abridged):

    TIME                 SEVERITY  TYPE           RULE             DETAIL
    2025-01-15T10:31:04Z critical  sqli.attempt   sqli.tautology   OR 1=1 tautology in query, user=dbguard db=dbguard_test
    2025-01-15T10:31:04Z high      pii.detection  pii.cc.tables    credit_card column referenced; masked in logs

Also useful:

    tail -n 5 /var/log/dbguard/alerts.jsonl     # alert sink output
    curl -s localhost:9701/metrics | grep events_total
    curl -s -X POST localhost:9700/api/v1/policies/reload -d '{}'

## 6. Full demo

    scripts/demo.sh          # SQLi batch, bulk dump, RIDS trigger

## Next steps

- `docs/architecture.md` - how the pieces fit together
- `docs/policies.md` - the policy DSL
- `deploy/k8s/` - DaemonSet deployment for Kubernetes

## Seeing SQLi / PII detections on live databases

dbguard captures SQL query text via uprobes on the DB server's internal
functions (postgres `exec_simple_query`, mysql `dispatch_command`). On stripped
distro binaries those symbols aren't resolvable, so only the byte-level
detectors (exfil) fire. Two options:

1. Install matching debug symbols (recommended, one-time):

       sudo make dbgsym      # adds the ddebs -updates/-security pockets,
                             # installs the EXACT-version dbgsym, and verifies
                             # the symbol is resolvable

   Restart dbguard; the log shows `uprobe attached (SQL query auditing active)`.

2. Run the whole thing in one shot (no terminal juggling):

       sudo make live-demo   # bg daemon -> attacks -> prints detections -> stop

To confirm the capture->detection pipeline independently of your DB binaries:

       sudo make verify-capture

## Query firewall & micro-segmentation
See docs/firewall.md for the configurable query firewall (allow/deny/rate/source
rules) and the eBPF/Cilium network micro-segmentation datapath.
