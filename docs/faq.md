# DBGuard FAQ

**Q1: Do I need root?**
Yes, to load and attach BPF programs and read /proc for identity.
Rootless mode runs userspace-only analysis (no kernel hooks) and is meant
for development against pcap-style inputs, not production.

**Q2: Does it run on macOS or Windows?**
No. DBGuard depends on Linux eBPF (BTF, ring buffers, cgroup hooks,
optionally BPF LSM). On non-Linux, use CI-compiled artifacts for review
and deploy to Linux hosts.

**Q3: What is the performance overhead?**
Per-event kernel work is bounded and O(1): fixed-size captures
(<= 512 bytes of SQL), a handful of map lookups. Ring buffer delivery is
asynchronous - the DB syscall never waits on userspace. On a 4-vCPU test
VM at ~10k queries/s, CPU overhead measured in the low single-digit
percent range; pipeline latency is microseconds (see
`pipeline_latency_seconds` histogram on :9701).

**Q4: What about TLS traffic between app and database?**
The wire hooks see ciphertext when DB TLS is on. DBGuard covers this via
uprobes on SSL_write/SSL_read (plaintext inside the process) and engine
dispatch symbols. Details and trade-offs: docs/threat-model.md.

**Q5: Which kernels are supported?**
Linux 5.8+ for ring buffers; 5.10+ recommended for full coverage
(cgroup_skb, LSM hooks, sk_lookup). Ubuntu 22.04/24.04, Debian 12, RHEL 9
class kernels are the supported matrix; CI compiles BPF on ubuntu-latest.

**Q6: Does SQLite work?**
SQLite is an embedded engine - there is no network protocol. DBGuard
attaches uprobes to sqlite3_exec/sqlite3_prepare_v2/v3 in any process
using SQLite, and supports TCP front-ends (e.g. litestream/steampipe)
via `ebpf.ports.sqlite_port`. The audit trail records the acting process
(comm, pid, cgroup) instead of a network peer.

**Q7: Too many false positives - how do I tune?**
Lower `sqli.sensitivity`, raise `sqli.confidence_threshold`, start every
policy rule as `actions: [alert]`, then flip to deny per rule after a week
of `rule_matches_total` data. Add allowlist rules with subject filters
(users/clients) ahead of the deny rules in filename order.

**Q8: Can I dry-run policies without enforcement?**
Yes - that is the default: `ebpf.drop_enabled: false` keeps all deny
actions advisory (they alert but never drop). Kernel-side drop, reset and
quarantine must be enabled explicitly per knob.

**Q9: SELinux, Ubuntu, aarch64?**
SELinux enforcing: the agent needs the usual BPF/sys_admin permissions
(the container path ships privileged; for hosts, run under unconfined or
a tailored module). Ubuntu kernels work out of the box. aarch64 is
supported by the Makefile (BPF_ARCH=arm64); verify your clang has the
BPF target for arm64.

**Q10: Migrating from dbWarden or other DB audit tools?**
Read the old tool's audit output with a one-off importer into DBGuard's
JSONL audit store (same record: one JSON object per line). Map existing
rules to policy documents (docs/policies.md); most "block list" regexes
map 1:1 onto `query.pattern` rules. Run DBGuard in alert-only mode in
parallel with the old tool until `rule_matches_total` shows parity.
