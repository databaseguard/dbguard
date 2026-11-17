# DBGuard threat model

Scope: the monitored database host (and, for multi-tenant features, its
tenants). DBGuard assumes the kernel itself is trustworthy; a kernel
compromise is out of scope (see residual risks).

## Assets and entry points

| Asset                              | Entry point used by an attacker            |
|------------------------------------|--------------------------------------------|
| PII in database tables             | SQL injection, stolen app credentials      |
| Database files (data directory)    | host-level shell on the DB server          |
| Backup/ETL channels                | insider abuse of legitimate bulk reads     |
| Session/pool capacity              | connection floods, pool hijack             |
| Tenant data boundaries             | cross-tenant queries through shared schema |

## Per-feature threat coverage

**1. SQL injection (sqli_firewall.bpf.c + internal/sqli + policy).**
Threat: injection through string interpolation in app code. Entry: any
client able to reach the DB port. Mitigation: kernel heuristics (cheap,
pre-TLS-termination at the socket) plus user-space parser and policy rules
(sqli.tautology/union/stacked/timebased). Enforced by cgroup_skb drop when
`ebpf.drop_enabled: true`. Residual: novel grammar-abusing payloads score
below `sqli.confidence_threshold`; tune sensitivity or add custom patterns.

**2. PII exfiltration via SELECT (audit.bpf.c + internal/pii + exfil).**
Threat: legitimate credentials used to dump tables (insider, stolen app
account). Mitigations: in-kernel pre-scan flags (Luhn-valid digit runs,
SSN-shaped patterns, high-entropy tokens), userspace PII detector with
masking, byte-density breaker (exfil_breaker.bpf.c), rate rules
(exfil.bulk, pii.bulk_select). Residual: small-per-query drip exfiltration
below rate thresholds; raise `exfil.max_rate_kbps` sensitivity or tighten
policy windows.

**3. Stolen credentials / pool hijack (conn_anomaly.bpf.c + anomaly).**
Threat: attacker reuses a valid DB account from an unusual source, or
drains/floods the pool to cause lockout or to ride an existing session.
Mitigations: per-client query-rate and connection-spike windows, concurrent
superuser-login cap, failed-auth streaks, client-IP identity in every
event. Residual: a patient low-and-slow account reuse inside normal rates;
combine with lineage (feature 6/8) to require app-route correlation.

**4. Host-level compromise (rids.bpf.c/rids_lsm + FIM).**
Threat: after any foothold on the DB host, an attacker spawns shells,
downloads tools, or reads data-directory files directly (bypassing SQL).
Mitigations: execve blocking of `blocked_binaries` when spawned from DB
process context, protected-path checks, FIM hash sweep of data dirs at
`rids.fim.interval_sec`. Alert-only by default; set `rids.alert_only:
false` to kill/freeze. Residual: fileless in-memory techniques and kernel
module loading (kernel compromise is out of scope).

**5. Cross-tenant attack (tenant_guard.bpf.c + internal/tenant + policy).**
Threat: one tenant's service account or container reads another tenant's
rows or files. Mitigations: cgroup/path tenant maps enforced in-kernel,
policy rules (tenant.a_isolation / tenant.b_isolation) with users+tables
matchers, FIM/protected paths per tenant. Residual: schema-sharing designs
where tenant keys live in row data (row-level isolation is the DB engine's
job; DBGuard observes those statements but cannot infer tenancy).

## TLS-wrapped database traffic (read this)

Honest limitation: DBGuard's wire hooks (cgroup_skb on the DB port) see
what the kernel sees. With PostgreSQL/MySQL TLS enabled, that is
**ciphertext** - the kernel pre-scan and the user-space wire parser cannot
extract SQL from it. Mitigations, in order of preference:

1. **Uprobes on the TLS boundary.** `ebpf.attach.openssl_symbols`
   (SSL_write/SSL_read) captures plaintext inside the process, before
   encryption, regardless of cipher choice. This is the default mitigation
   and requires no config for stock OpenSSL builds.
2. **kTLS / kernel TLS offload.** If the stack uses kTLS, records are
   encrypted in-kernel after the hooks' visibility point, restoring wire
   visibility for the crypto-offload path.
3. **Deployment pattern.** Terminate app->DB TLS at a local sidecar or
   unix-socket proxy on the same host and keep the loopback hop plaintext;
   DBGuard then sees the loopback leg.

Note the uprobe path also covers non-OpenSSL builds via the engine-specific
symbols (`postgres_symbols`, `mysql_symbols`) which see plaintext SQL at
the dispatch functions regardless of transport.

## What DBGuard does NOT do

- No replacement for database authN/authZ, TLS configuration or patching.
- No detection of kernel-level rootkits (assumption: kernel trusted).
- No row-level authorization; tenant isolation is path/cgroup/statement
  based, not row based.
- No storage of query results beyond capped snippets (max_sql_len,
  DBG_MAX_SQL) - the audit trail holds metadata + redacted SQL, not dumps.
