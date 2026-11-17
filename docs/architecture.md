# DBGuard architecture

## Overview diagram

    HOST (Linux 5.8+, root)
    ============================================================================
      PostgreSQL (5432)                MySQL (3306)            app processes
           |                                |                       |
           |  uprobes: exec_simple_query    |  uprobes: dispatch_*  |  uprobes:
           |  pg_parse_query                |  (mangled variants)   |  SSL_write, route fns
           v                                v                       v
    +---------------------------------------------------------------------------+
    | KERNEL (bpf/src/*.bpf.c)                                                  |
    |                                                                           |
    |  audit.bpf.c        query capture + PII pre-scan flags (Luhn/SSN/entropy) |
    |  sqli_firewall.bpf.c  wire-level SQLi heuristics (+ optional drop)        |
    |  conn_anomaly.bpf.c   per-client rate/spike/auth-failure accounting       |
    |  exfil_breaker.bpf.c  byte-density windows per session                    |
    |  rids.bpf.c          execve/file hooks (LSM variant: rids_lsm.bpf.o)      |
    |  lineage.bpf.c        app-route <-> DB session correlation                |
    |  tenant_guard.bpf.c   cgroup/path isolation checks                        |
    |  microseg_xdp.bpf.c   XDP/sockmap micro-segmentation (optional)           |
    |                                                                           |
    |  config_map (userspace -> kernel knobs)      ringbufs (kernel -> userspace)
    +-----------------------------|---------------------------------------------+
                                  | ringbuf records (dbg_hdr + payload)
                                  v
    +---------------------------------------------------------------------------+
    | USERSPACE (Go, github.com/databaseguard/dbguard)                                |
    |                                                                           |
    |  internal/ebpf     loader/manager: load objects, attach, decode records   |
    |  internal/enrich   identity resolution (pid,cgroup -> container/pod)      |
    |  internal/identity cgroup/container/Cilium resolver implementations       |
    |  internal/proto    PostgreSQL/MySQL wire parsers (user-space depth)       |
    |  internal/pipeline events -> enrich -> detect (below) -> policy -> sinks  |
    |  internal/detect   Detector contract; modules:                            |
    |       pii/ sqli/ anomaly/ exfil/ rids/ lineage/ tenant/                   |
    |  internal/policy   firewall engine (YAML rules, rate limiter, hot reload) |
    |  internal/alert    router + sinks: webhook, slack, syslog, file(JSONL)    |
    |  internal/audit    JSONL audit store with rotation + PII redaction        |
    |  internal/api      admin REST :9700  |  internal/metrics  Prometheus :9701|
    +---------------------------------------------------------------------------+

## Feature-to-code map

| # | Feature                     | Kernel program            | Userspace path            |
|---|-----------------------------|---------------------------|---------------------------|
| 1 | Audit + PII detection       | audit.bpf.c               | internal/audit, internal/pii, internal/proto |
| 2 | Micro-segmentation          | microseg_xdp.bpf.c        | internal/identity (Cilium), deploy/cilium/   |
| 3 | Runtime intrusion detection | rids.bpf.c (+LSM variant) | internal/rids                |
| 4 | Connection anomaly          | conn_anomaly.bpf.c        | internal/anomaly             |
| 5 | SQL injection firewall      | sqli_firewall.bpf.c       | internal/sqli, internal/policy |
| 6 | App-to-DB lineage           | lineage.bpf.c             | internal/lineage             |
| 7 | Bulk-dump breaker           | exfil_breaker.bpf.c       | internal/exfil               |
| 8 | Dual-sided context matcher  | lineage.bpf.c + uprobes   | internal/lineage (runtime_probes) |
| 9 | Multi-tenant guard          | tenant_guard.bpf.c        | internal/tenant              |

Shared definitions live in `bpf/include/dbguard/common.h` (wire structs,
event types, severity/action enums) mirrored by `internal/ebpf/types.go`
and decoded in `internal/ebpf/decode.go`. Changing a struct there requires
updating both sides.

## Data flow: one SQL injection attempt

    1. client -> "SELECT .. WHERE id='' OR 1=1 --" over TCP :5432

    2. KERNEL  cgroup_skb (postcard at socket layer, port-matched 5432)
       - sqli_firewall heuristics score the payload
       - flags DBG_QF_SQLI_HINT set; if drop_enabled, packet is dropped here
       - query event (dbg_query_event) written to ringbuf

    3. KERNEL  uprobe on postgres!exec_simple_query (fires milliseconds
       later, authoritative SQL text) -> second query event

    4. USERSPACE internal/ebpf decodes both records into events.Event
       (deduped by session cookie), pipeline enriches:
         - identity: pid -> /proc/<pid>/cgroup -> container id -> pod
         - proto:    PostgreSQL parser extracts SQL/user/database

    5. USERSPACE detectors run in order (pii, sqli, anomaly, exfil, ...);
       the SQLi detector raises confidence 0.9+ and adds finding
       sqli.tautology.

    6. USERSPACE policy engine evaluates configs/policies/*.yaml in
       filename order; rule sqli.tautology matches -> actions [deny, alert]:
         - deny: if ebpf.drop_enabled, kernel map updated to drop the
           offender's next packets; else the session is marked denied
         - alert: event severity critical, actions annotated

    7. USERSPACE fan-out:
         - internal/alert router -> webhook/slack/syslog/file sinks
           (severity gate + 60s dedupe per rule+subject)
         - internal/audit -> /var/lib/dbguard/audit/*.jsonl (PII redacted)
         - internal/metrics -> events_total, findings_total, rule_matches_total

    8. Operators: dbguard-cli events / alerts.jsonl / Prometheus / webhooks.

## Design principles

**Userspace/kernel split.** The kernel does bounded, fixed-cost work:
capture, cheap heuristics on capped buffers (DBG_MAX_SQL = 512 bytes), byte
accounting, enforcement. Everything context-aware (regex policies, entropy,
protocol state machines, alerting) lives in Go. Kernel decisions can never
depend on unbounded input.

**Fail-open vs fail-closed.** `ebpf.drop_enabled: false` (default) means
DBGuard observes and alerts but never blocks - the safe posture for a new
deployment. `drop_enabled: true` arms cgroup_skb drop for deny rules. The
daemon also degrades gracefully: if a BPF feature is unavailable (no LSM
hooks, older kernel), that module runs in userspace-only mode and the
missing kernel enforcement is logged at startup.

**No-LSM fallback.** `rids_lsm.bpf.o` (built with DBGUARD_ENABLE_LSM) can
block execve/file operations at the LSM layer when the kernel supports
BPF LSM. Without it, RIDS still observes via tracepoints/uprobes and
enforcement falls back to SIGKILL/cgroup-freeze issued from userspace.

**Asynchronous by construction.** All kernel->userspace transport is ring
buffers; a slow consumerspace only drops new records (countered in
metrics), never blocks a syscall. Ring size is `ebpf.ringbuf_pages`.

**One event model.** Every module emits the same `events.Event`; policy,
alerts, audit and metrics all consume the same shape, so a new detector
needs no changes in the sinks.
