<div align="center">

# dbguard

### An eBPF-powered, identity-aware database firewall for PostgreSQL and MySQL

See every query your databases run. Decide which ones are allowed to.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.22%2B-00ADD8.svg)](https://go.dev/)
[![Platform](https://img.shields.io/badge/platform-Linux%20eBPF-333.svg)](https://ebpf.io/)
[![Databases](https://img.shields.io/badge/databases-PostgreSQL%20%7C%20MySQL-336791.svg)](#)
[![Docs](https://img.shields.io/badge/docs-databaseguard.github.io-blue.svg)](https://databaseguard.github.io/)

[**Documentation**](https://databaseguard.github.io/) ·
[Quick start](#quick-start) ·
[How it works](#how-it-works) ·
[Writing policies](#writing-policies)

</div>

---

## What is dbguard?

dbguard is a **database firewall**. It inspects the SQL statements your PostgreSQL and
MySQL servers actually execute and enforces a policy you define - allowing, auditing,
masking, rate-limiting, or outright blocking individual queries.

Unlike tools that sniff network packets or scrape logs after the fact, dbguard attaches to
the database process itself with **eBPF** and observes each statement at the moment it is
parsed. That means it sees the real query, with full fidelity, regardless of TLS, connection
pooling, or wire-protocol quirks. When you need a hard guarantee rather than an alert, the
same policy engine runs inline as a proxy, refusing a statement before it ever reaches the
server.

On Kubernetes clusters running Cilium, dbguard becomes **identity-aware**: every query can
be attributed to the workload that issued it, so a rule can be written in terms of "the
billing service" rather than a brittle IP address.

## Why a database firewall?

Traditional database security answers one question - *who is allowed to connect* - and
stops there. The queries that flow through an authenticated connection go unexamined. That
leaves familiar gaps:

- A compromised or over-privileged application account can read or modify anything its role
  permits.
- A bulk export of sensitive columns is indistinguishable from any ordinary `SELECT`.
- A malformed or injected statement reaches the engine before anyone notices.
- An accidental `UPDATE` or `DELETE` without a `WHERE` clause is valid SQL until it isn't.

dbguard closes those gaps by governing the **statement**, not just the session. Every query
is evaluated against your policy and recorded with a verdict, giving you both a continuous
audit trail and an enforcement point.

## Key capabilities

| Capability | What it does |
|---|---|
| **Full-fidelity auditing** | Captures every statement on PostgreSQL and MySQL via eBPF, enriched with user, database, client, and workload identity. |
| **Inline enforcement** | An optional proxy evaluates queries before they reach the database and returns a clean error on a block - synchronous and guaranteed. |
| **SQL-injection firewall** | Ships with rules for the common injection shapes (UNION extraction, boolean and time-based probes, stacked statements) that you can tune or extend. |
| **Sensitive-data controls** | Deny or mask queries that touch columns such as `ssn`, `credit_card`, or `password`. |
| **Write protection** | Refuse writes by table, column, or statement shape - for example, block any `UPDATE` on a protected table. |
| **Rate limiting** | Throttle a query pattern per user, client, or identity to catch scripted abuse and bulk exfiltration. |
| **Identity-based rules** | On Cilium, allow or deny by the client's workload identity instead of its IP address. |
| **Hot-reloaded policy** | Policies are plain YAML, loaded from a directory and reloaded on change with no restart. |

## How it works

dbguard runs two complementary planes, and you can use either or both.

**Detection plane - your eyes.**
An eBPF uprobe attaches to the database's query-parsing function. Nothing is injected into
the database and no traffic is duplicated; dbguard simply observes each statement as the
server begins to handle it, adds context, and runs it through the policy engine. This plane
is ideal for auditing, alerting, and visibility. Because it reacts to an event the kernel
has already delivered, its blocking is best-effort - a very fast query can complete before
the verdict is reached - so treat it as observation and reactive response.

**Enforcement plane - your lock.**
The same policy engine runs inline as a proxy. Point an application at the proxy port and
every statement is evaluated *before* it is forwarded; a denied query never reaches the
database and the client receives a clear error. This is the plane to use when a block must
be guaranteed.

Both planes share one policy engine. It loads every YAML file in a policy directory in
filename order, evaluates each query against all enabled rules, and stops at the first rule
that denies. Files are watched and reloaded on the fly, so rules can be added or removed on
a running agent without downtime.

```
                       ┌──────────────────────────────┐
   application ───────▶│   enforcement plane (proxy)   │──▶ database
        │              │   evaluate → allow / block    │
        │              └──────────────────────────────┘
        │                          ▲
        ▼                          │  shared policy engine
   ┌─────────────┐        ┌────────┴─────────┐
   │   database   │◀──────│  detection plane │   eBPF uprobe on the
   │   process    │ uprobe│   observe + audit│   query parser
   └─────────────┘        └──────────────────┘
```

## Quick start

**Requirements:** Linux with a recent kernel, clang/LLVM to compile the eBPF objects, and
Go 1.22 or newer. The agent runs privileged (root, or `CAP_BPF` with `CAP_SYS_ADMIN`)
because it loads eBPF programs and attaches probes.

```bash
git clone https://github.com/databaseguard/dbguard && cd dbguard

make bpf        # compile the eBPF objects
make go-build   # build dbguardd and dbguard-cli
make test       # run the unit tests

sudo ./build/bin/dbguardd -config configs/dbguard.yaml
```

With the daemon running, issue a few queries and read them back from the API, or point an
application at the proxy port to put a rule directly in the request path. The
[installation](https://databaseguard.github.io/) and quick-start guides cover both a
single-host `systemd` setup and a Kubernetes DaemonSet.

## Writing policies

Policies are YAML. Each rule combines *subject* filters (who and what - engine, user,
client, identity, table, column) with a *content* matcher on the SQL, and a set of actions
to take on a match.

```yaml
api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata: { name: employees }
spec:
  default_action: allow
  rules:
    - id: emp.no-update
      tables: [employees]
      query: { pattern: '(?i)^\s*update\b' }
      actions: [deny, alert]        # refuse any UPDATE on this table

    - id: emp.mask-pii
      tables: [employees]
      columns: [salary, ssn]
      actions: [alert, mask]         # reads still work; sensitive fields are masked
```

Test a rule against a statement before you deploy it - no database required:

```bash
dbguard-cli dry-run --engine postgres --sql "UPDATE employees SET salary = 0 WHERE id = 1"
# -> denied, rule emp.no-update
```

The [rule-writing cookbook](https://databaseguard.github.io/) in the documentation walks
through write protection, column- and value-level rules, allow-lists, and the
parameterized-query caveats in detail.

## Running on Kubernetes

dbguard deploys as a DaemonSet so one agent per node can observe the database processes on
that node. The manifests under `deploy/k8s` set up the agent, and `deploy/cilium` includes
an example network policy for pairing statement-level control with L3/L4 segmentation. The
Kubernetes guide covers the details that matter - why the agent needs `hostPID` but
deliberately avoids `hostNetwork`, how workload identity is resolved through the Cilium
agent, and how to hot-load a rule into a running pod.

## Repository layout

```
cmd/         the dbguardd daemon and the dbguard-cli admin tool
bpf/         eBPF C sources and shared headers
internal/    Go packages - ebpf, proxy, policy, pipeline, identity, pii, and more
configs/     a sample dbguard.yaml and a starter policy bundle
deploy/      Dockerfile, Kubernetes manifests, Cilium policy, systemd unit
docs/        design notes
test/        integration tests
```

## Documentation

The complete guide - architecture, data flow, the policy language, a rule-writing cookbook,
deployment, and a full configuration and CLI reference - is published at
**[databaseguard.github.io](https://databaseguard.github.io/)**.

## License

dbguard is released under the **MIT License** - use it, modify it, and build on it freely;
just keep the copyright notice. See [LICENSE](LICENSE).

The eBPF C sources under `bpf/` are dual-licensed `GPL-2.0-only OR MIT`. Those programs
declare `GPL` to the kernel at load time because the eBPF helpers they use require it; that
is a kernel rule about what the program may call, not a restriction on your copy of the
source, which you may still take under MIT. See [bpf/LICENSE](bpf/LICENSE).
