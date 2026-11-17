# Query Firewall - "iptables for SQL"

dbguard includes a configurable, network-firewall-style rule engine for database
queries. Rules live in `configs/policies/*.yaml`, hot-reload on change, and are
evaluated top-to-bottom; the first matching rule decides the verdict.

## What you can match on

| Dimension | Field | Example |
|-----------|-------|---------|
| Source IP / subnet | `clients` | `[10.20.0.0/16, 127.0.0.1]` |
| DB user / role | `users` | `[app_ro, reporting]` |
| Engine | `engines` | `[postgres, mysql]` |
| Database / schema | `databases` | `[prod]` |
| Tables referenced | `tables` | `[customers, payments]` |
| Columns referenced | `columns` | `[ssn, credit_card]` |
| SQL text (regex) | `query.pattern` | `'(?i)drop\s+table'` |
| SQL text (substrings) | `query.keywords` | `[into outfile, load_file]` |
| Rate | `rate: {events, window}` | `{events: 200, window: 10s}` |

## Actions

`allow`, `deny` (drop/reset the connection when `ebpf.drop_enabled: true`),
`alert`, `block`, `reset`. A denying action stops evaluation and enforces;
alerting actions annotate and continue. `default_action` (allow/deny) applies
when no rule matches - use `deny` for a zero-trust allowlist.

## Test a query against the firewall (no live DB needed)

```bash
# read-only user attempting a write -> DENY
dbguard-cli dry-run -c configs/dbguard.dev.yaml -e postgres -u app_ro -d prod \
  "DELETE FROM customers WHERE id=1"

# normal SELECT from the app user -> ALLOW
dbguard-cli dry-run -c configs/dbguard.dev.yaml -e postgres -u app_rw \
  "SELECT id,name FROM products WHERE price < 100"
```

It prints the decision, the matched rule, the actions and the reason - like
`iptables -C`. See `configs/policies/60-query-firewall.yaml` for a complete,
commented example covering source control, read-only enforcement, column
protection, DDL blocking, file-primitive blocking and two rate limits.

## Rate limiting

`rate` throttles the matched subject with a sliding window. The subject key is
(engine, database, user, client). Example - cap any client to 200 queries / 10s:

```yaml
- id: fw.rate-per-client
  clients: [0.0.0.0/0]
  rate: { events: 200, window: 10s }
  actions: [deny, alert]
```

# Zero-Trust Network Micro-Segmentation (eBPF / Cilium)

Feature 2 is implemented as a socket-layer datapath:

- `bpf/src/microseg_sockmap.bpf.c` - `stream_parser` + `stream_verdict` +
  `sk_msg_redirect` over a `sockhash`, the Cilium-sockmap acceleration path.
- `bpf/src/microseg_xdp.bpf.c` - `xdp_microseg` drops unauthorized TCP SYNs to
  the DB port before they reach the auth layer.
- `client_allow` LPM-trie map, populated from the control plane
  (`Manager.UpdateClientPolicy`) and from the Cilium identity resolver
  (`internal/identity/cilium.go`), so only approved pod identities / CIDRs may
  open a connection to the database port.
- Deploy manifests in `deploy/cilium/` (CiliumNetworkPolicy for postgres/mysql,
  sockmap enablement, Hubble notes).

Enable XDP enforcement by listing the DB-facing interface in
`ebpf.xdp_interfaces` and the allowed client CIDRs via the control plane; see
`docs/k8s-cilium.md`.

## Proving your firewall rules

`scripts/test-firewall.sh` (`make test-firewall`) writes a throwaway policy with
ONE rule per matcher dimension and verifies each enforces exactly as written:
SQL pattern, SQL keywords (ANY-of), DB user, source IP/CIDR, engine, database,
combined matchers, and a default-deny allowlist. 23 checks, all must pass. Run it
after editing rules to confirm your intent matches the engine's behavior.

Evaluation order is first-match-wins (like a network firewall): the first rule
whose matchers all match decides the verdict. A `deny` action blocks and stops;
an explicit `allow` action permits and stops (this is what makes a
`default_action: deny` allowlist work); `alert`/`mask` annotate and continue.

## Hands-on demos (seed data → rule → blocked; and rate limiting)

Two scripts walk through it live:

```bash
sudo make demo-rule   # seeds a secrets table, shows a SELECT returns rows,
                      # adds a rule blocking that table, shows the query is DENIED
sudo make demo-rate   # caps queries/window, fires a burst, shows allowed→denied
```

Note on testing table/column rules: `dbguard-cli dry-run` now extracts tables
and columns from the SQL (like the live pipeline), so `tables:`/`columns:` rules
can be checked offline:

```bash
dbguard-cli dry-run -c configs/dbguard.dev.yaml -e postgres "SELECT * FROM salaries"
# with a rule {tables: [salaries], actions: [deny]} -> decision: DENY
```

Rate rules can only be observed live (the daemon holds the sliding window); a
per-call CLI resets it. The sliding-window logic itself is proven by
`go test ./internal/policy -run TestRateLimitThrottle`.

## Enforcement mode: detect vs drop

By default (`ebpf.drop_enabled: false`) dbguard runs in **detect-and-alert**: a
denied query is recorded (`allowed: false`, rule id, alert sinks) but the client
connection is not severed, so the query may still return. To make denials
**actually block the client** (query fails / connection reset), set
`ebpf.drop_enabled: true` and, for the XDP paths, list the DB-facing interface in
`ebpf.xdp_interfaces`. This is the standard fail-open vs fail-closed choice.

## Network micro-segmentation status (feature 2)

- `xdp_microseg` (XDP): drops packets to the DB port from clients not in the
  `client_policy` allowlist; verified to load, attach to a live interface, and
  carry its LPM-trie policy map (`scripts/test-microseg.sh`).
- `microseg_sockmap`: the Cilium-style socket-layer redirect datapath
  (stream_parser/verdict + sk_msg over a sockhash).
- Cilium integration is OPTIONAL: with a local Cilium agent, events are enriched
  with the pod security identity behind each IP; without it, everything else
  works. Full pod-identity enforcement needs a running Cilium + Kubernetes
  cluster (manifests in `deploy/cilium/`). Run `sudo make test-microseg`.

## Making queries actually FAIL at the client (drop_enabled)

By default dbguard is detect-and-alert: a denied query is recorded but the
client still gets its rows. To make a denied query **fail at the terminal**:

1. set `ebpf.drop_enabled: true` in `configs/dbguard.dev.yaml`
2. restart dbguard

Now when a statement is DENIED by policy (SQLi, a rate limit, a firewall rule),
dbguard terminates the offending DB backend and the client sees:

```
FATAL:  terminating connection due to administrator command
```

This uses a per-backend SIGTERM (PostgreSQL ends just that session; the server
and other sessions are unaffected). Example - a 3/min rate rule, queries fired
one at a time:

```
query 1: 1          query 4: FATAL: terminating connection ...
query 2: 2          query 5: FATAL: terminating connection ...
query 3: 3          query 6: FATAL: terminating connection ...
```

## Enforcement timing - read this to set expectations correctly

dbguard captures queries via uprobe on the DB's parser, which is **asynchronous**:
the query is observed, then the verdict is computed in userspace, then (on deny)
the backend is terminated. There is a small enforcement latency (~5-10 ms) between
"query observed" and "connection killed". The consequence:

- **Slow / substantial queries** - bulk dumps, `SELECT *` over big tables,
  time-based injection (`pg_sleep`), anything taking longer than the enforcement
  latency - are **killed mid-flight; the data does NOT return** (verified: a
  denied `SELECT pg_sleep(3)` is terminated in ~50 ms with no rows). These are
  exactly the queries that matter for exfiltration and injection.

- **Trivial microsecond queries** (`SELECT 1`) can finish and return their row
  *before* the kill lands. The session is still terminated (the connection drops
  and subsequent queries on it fail), and the event is recorded `allowed:false`,
  but the single tiny result may already be on the wire.

This is inherent to asynchronous uprobe enforcement (the same trade-off all
uprobe-based DB monitors have). For hard, synchronous, pre-result blocking you
need an inline data-path proxy or an LSM hook; dbguard's model is
detect-everything + terminate-the-session + (for network-layer rules) in-kernel
XDP/cgroup drop.

### Deterministic rate limiting: quarantine the source

For rate limits where you want the *next* attempt hard-refused (not just the
current session killed), pair the rule with source quarantine: once a client
trips the limit, its IP is dropped in-kernel (XDP/cgroup) for a cooldown, so new
connections are refused before any query runs. This is synchronous and does not
race. (Not applicable to 127.0.0.1, which is never quarantined.)

## Synchronous inline proxy - hard pre-result blocking (the no-race path)

The uprobe path is asynchronous, so a trivial microsecond query can return its
row before the kill lands. The **inline proxy** closes that gap completely:
clients connect to the proxy, which parses the PostgreSQL wire protocol, runs
every Query/Parse through the SAME policy engine, and forwards only allowed
statements. A denied query is rejected with a PostgreSQL ErrorResponse and is
NEVER sent to the database - so no rows can return, regardless of speed.

Enable it:

```yaml
proxy:
  enabled: true
  listen: 127.0.0.1:6432     # point your app here
  upstream: 127.0.0.1:5432   # the real database
  engine: postgres
```

Then connect to the proxy (plaintext; the proxy declines SSL so it can inspect):

```bash
psql "host=127.0.0.1 port=6432 user=dbguard password=dbguard dbname=dbguard_test sslmode=disable" \
  -tAc "SELECT * FROM secrets"
# -> ERROR: dbguard: query blocked by policy (rule block.secrets)
#    the database never received the query; zero rows returned
```

Proxy vs uprobe - use both: the proxy gives hard, synchronous blocking for
traffic you route through it; the uprobe path audits/enforces direct and local
connections that bypass the proxy. Together they cover both routes.
