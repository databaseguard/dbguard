# Observing database flows with Hubble

Hubble (the Cilium observability layer) and DBGuard answer different
questions about the same traffic: Hubble sees L3/L4 (and selected L7
protocols) between workloads; DBGuard sees the database session itself --
statements, users, PII columns, byte-volume bursts -- from inside the kernel
via eBPF on the DB host. Together they give both the "who talked to whom"
view and the "what was said to the database" view.

## Useful commands

List live PostgreSQL flows (any direction):

    hubble observe --namespace dbguard \
        --protocol tcp --to-port 5432 --follow

Show only denied flows (Cilium policy verdicts) toward the databases:

    hubble observe --namespace dbguard --verdict DROPPED --follow

Identity of a client pod as Cilium sees it:

    cilium-dbg endpoint list | grep api-server
    hubble observe --from-label k8s:app=api-server --to-label k8s:app=postgres

Export flows for offline correlation with DBGuard audit JSONL:

    hubble observe --output json --to-port 5432 > hubble-pg.json

## How DBGuard complements Hubble

- Hubble answers "which pod talked to postgres:5432, when, how much?" and
  enforces L3/L4 segmentation (see the CiliumNetworkPolicy files in this
  directory). A stolen credential inside an allowed path is invisible to it.
- DBGuard answers "which statement did that session run, which user/columns
  did it touch, was the payload injected?" and enforces at the statement
  level (deny, quarantine, rate-limit). It also resolves identity down to
  cgroup/container via internal/identity, using the same Cilium identity
  ids when available (identity.cilium_enabled in dbguard.yaml).
- Correlating the two: DBGuard events carry client_ip/pod/namespace; Hubble
  flows carry the same pod labels and Cilium security identity. Joining on
  client IP + time window in your SIEM reconstructs the full path from HTTP
  request to SQL statement.
