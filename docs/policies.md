# DBGuard policy DSL reference

Policy documents are YAML files under `configs/policies/` (or
`policies.dirs`). Schema source: `internal/policy/rules.go`. Validate:

    dbguard-cli validate-policy configs/policies

## Document skeleton

    api_version: dbguard.io/v1     # required, literal
    kind: DbGuardPolicy            # required, literal
    metadata:
      name: my-policy              # required
      description: ...             # optional
      labels: {tier: firewall}     # optional, free-form
    spec:
      default_action: allow        # verdict when no rule matches: allow|deny
      rules:
        - id: my.first_rule        # unique across documents (metrics label)
          ...

## Rule fields

| Field         | Type     | Meaning                                            | Example                                  |
|---------------|----------|----------------------------------------------------|------------------------------------------|
| id            | string   | unique rule id (events, metrics, dedupe key)       | sqli.tautology                            |
| name          | string   | human title                                        | Tautology bypass                          |
| description   | string   | free text                                          |                                           |
| enabled       | bool     | optional; default true; false silences the rule    | false                                     |
| severity      | string   | info|low|medium|high|critical                      | critical                                  |
| engines       | []string | subject filter: postgres|mysql|sqlite (empty=all)  | [postgres, mysql]                         |
| databases     | []string | subject filter on database name (empty=all)        | [dbguard_test]                            |
| users         | []string | subject filter on DB user (empty=all)              | [tenant_b_svc]                            |
| clients       | []string | subject filter on client IP/CIDR (empty=all)       | [10.0.0.0/8]                              |
| identities    | []string | subject filter on Cilium security identity: id or label/substring (needs identity.cilium_enabled) | [k8s:app=api-server] |
| tables        | []string | object filter parsed from SQL (empty=all)          | [customers]                               |
| columns       | []string | object filter on referenced columns (empty=all)    | [credit_card, ssn]                        |
| query         | object   | content matcher, see below                         |                                           |
| rate          | object   | rate limiting, see below                           |                                           |
| actions       | []string | decisions taken on match                           | [deny, alert]                             |

### query (QueryMatcher)

| Field            | Type | Meaning                                                       |
|------------------|------|---------------------------------------------------------------|
| pattern          | str  | Go regexp (RE2) matched against the SQL text                  |
| keywords         | []str| ANY-of substring alternative to pattern                       |
| case_insensitive | bool | folds case for keywords (patterns: use (?i) instead)          |
| min_length       | int  | skip SQL shorter than this (noise reduction)                  |

Empty query matches every statement (subject/object filters still apply).

### rate (RateRule)

    rate:
      events: 3        # at most N matches...
      window: 10s      # ...per window per subject key (user+client+rule)

Windows accept s/m/h. When the limiter trips, the rule's actions apply;
further matches inside the same window are suppressed (one alert, not N).

## Matching semantics

1. Documents load in filename order (00- before 50-); within a document,
   rules evaluate in list order.
2. All filters must pass for a rule to match: severity/actions apply on
   the first matching rule that yields a **denying** action.
3. **First-deny-wins**: evaluation stops at the first rule that decides
   deny/drop/reset/kill/freeze; alerting-only rules annotate and continue.
4. If nothing matches, `spec.default_action` applies.
5. A match is recorded (`rule_matches_total{rule}`) even for alert-only.

## Actions catalogue and kernel mapping

| Action      | Effect                                              | Kernel mechanism                          |
|-------------|-----------------------------------------------------|-------------------------------------------|
| allow       | explicit allow (stops deny evaluation)              | none (verdict only)                       |
| alert       | annotate event, route to sinks                      | none (userspace)                          |
| deny        | reject the statement/session                        | cgroup_skb DROP (needs ebpf.drop_enabled) |
| drop        | same as deny, explicit packet drop                  | cgroup_skb DROP                           |
| reset       | terminate the client connection                     | TCP RST injection via quarantine map      |
| rate_limit  | throttle matching subjects                          | per-subject token bucket (userspace)      |
| mask        | redact detected PII in logs/audit/alerts            | none (userspace)                          |
| kill        | SIGKILL the offending process                       | RIDS kill path (rids.alert_only=false)    |
| freeze      | freeze the offending cgroup                         | cgroup v2 freezer                         |
| quarantine  | put the session/cgroup on the quarantine map        | kernel map + expiry (exfil.quarantine_sec)|

Enforcement-level actions (deny/drop/reset/kill/freeze/quarantine) require
the corresponding kernel capabilities; where a mechanism is unavailable
(no LSM, drop disabled) the daemon logs the fallback and still alerts.

## Four complete examples

**1. Block UNION extraction everywhere (see 20-sql-firewall.yaml):**

    - id: sqli.union
      severity: critical
      query:
        pattern: '(?i)union\s+(all\s+)?select'
      actions: [deny, alert]

**2. Mask PII columns but never block (10-pii-protection.yaml):**

    - id: pii.cc.tables
      severity: high
      tables: [customers, employees]
      columns: [credit_card, ssn, salary]
      query:
        pattern: '(?i)(select|insert|update).*(credit_card|ssn|salary)'
      actions: [alert, mask]

**3. Rate-limit nightly backup tool only (subject filter):**

    - id: backup.allow_bulk
      severity: info
      users: [backup_svc]
      clients: [10.0.4.0/24]
      query:
        pattern: '(?i)select\s+\*'
      rate:
        events: 100
        window: 1m
      actions: [alert]

**4. Cross-tenant deny (40-tenant-isolation.yaml):**

    - id: tenant.b_isolation
      severity: critical
      tables: [users_tenant_b]
      users: [tenant_a_svc]
      actions: [deny, alert]

## Versioning and best practices

- Keep `api_version: dbguard.io/v1`; future schema changes bump it and the
  loader refuses unknown versions.
- Name files `NN-purpose.yaml`; the numeric prefix documents evaluation
  order. Do not encode order semantics into a single file.
- Start in observe mode: `actions: [alert]` everywhere, review
  `rule_matches_total` for a week, then flip high-confidence rules to deny.
- Every deny rule should carry a comment describing its false-positive
  posture and an id you can grep alerts by.
- Test changes: `dbguard-cli validate-policy` in CI, plus
  `scripts/demo.sh` against a staging host before rollout.
