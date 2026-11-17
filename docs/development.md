# Development guide

## Repository layout

    dbguard/
    |-- bpf/                    kernel-side C
    |   |-- include/dbguard/    common.h (wire structs), helpers.h
    |   `-- src/                *.bpf.c programs (one per feature)
    |-- cmd/
    |   |-- dbguardd/           daemon entrypoint
    |   `-- dbguard-cli/        operator CLI
    |-- configs/
    |   |-- dbguard.yaml        reference config
    |   `-- policies/           numbered policy documents
    |-- deploy/                 Dockerfile, compose, k8s/, cilium/
    |-- docs/                   architecture, threat model, DSL, protocols
    |-- internal/               all Go packages (no public API)
    |   |-- ebpf/               loader, attach, ringbuf decode
    |   |-- events/             canonical Event model
    |   |-- pipeline/           enrich -> detect -> policy -> sinks
    |   |-- detect/             Detector/Runner contracts
    |   |-- {pii,sqli,anomaly,exfil,rids,lineage,tenant}/
    |   |-- proto/              PostgreSQL/MySQL wire parsers
    |   |-- policy/             firewall engine + hot reload
    |   |-- alert/              router + sinks (webhook/slack/syslog/file)
    |   |-- audit/              JSONL audit store
    |   |-- metrics/            Recorder + Prometheus implementation
    |   |-- identity/           cgroup/container/Cilium resolver
    |   |-- enrich/             Resolver contract + cache
    |   `-- {config,logging,version}/
    |-- scripts/                install/setup-dbs/demo/load-policy/verify
    `-- test/integration/       compose-based attack simulation

## Add a detector (userspace analysis module)

1. Create `internal/<name>/` with a type implementing
   `detect.Detector` (Name() + Evaluate(*events.Event) []events.Finding);
   add `detect.Runner` if it needs background loops.
2. Mutate the event for enforcement: `ev.AddAction(events.ActDeny)` etc.
   Attach context with `ev.MetaSet(k, v)`.
3. Register in the daemon wiring (pipeline construction in
   `cmd/dbguardd`), gated on its config section.
4. Add a config section to `internal/config` (yaml tag + defaults +
   validation) and document it in `configs/dbguard.yaml`.
5. Unit tests: table-driven, inject `*events.Event`s; detectors must be
   safe for concurrent Evaluate calls.

## Add a BPF program

1. Add `bpf/src/<name>.bpf.c`; include `dbguard/common.h`, define
   `LICENSE` = DBGUARD_LICENSE, reuse `dbg_fill_hdr()` for event headers.
2. Reuse the shared ringbuf pattern; do not introduce per-program maps
   without pinning them under `ebpf.pin_path`.
3. The Makefile compiles every `*.bpf.c` in `bpf/src` automatically
   (`make bpf`); add an explicit rule only for variants (see
   rids_lsm.bpf.o built with -DBGUARD_ENABLE_LSM).
4. Update the attach table in the loader (`internal/ebpf`) and, if you add
   a wire struct, mirror it in `internal/ebpf/types.go` +
   `internal/ebpf/decode.go` and bump nothing in common.h casually -
   structs are packed and binary-compatible.
5. Kernel-config knobs go through `config_map` (struct dbg_config), not
   compile-time constants.

## Testing strategy

- **Unit**: `go test ./internal/...` - parsers, policy engine, alert
  router (httptest sinks), identity resolver (fixture /proc trees).
- **Verifier smoke**: after `make bpf`, `llvm-objdump -h` each object to
  confirm BPF machine code; on a VM with 5.8+ kernel, run
  `sudo ./build/bin/dbguardd` and `bpftool prog list` / `tc filter show`
  to confirm attachments.
- **Integration**: `test/integration/run.sh` boots postgres+mysql+dbguard
  under compose, runs `attack_sim.sh` in the attacker container and greps
  the audit JSONL for expected detection ids.
- **CI**: `.github/workflows/ci.yml` runs vet, tests and compiles BPF
  objects on ubuntu-latest.

## Coding standards

- Go 1.22, gofmt tabs, doc comments on every exported symbol.
- Errors: wrap with `%w`, prefix with the package (`alert:`, `policy:`).
- Concurrency: document the lock discipline on types with mutexes;
  hot-path code must not allocate per event where avoidable.
- Allowed dependencies: stdlib, gopkg.in/yaml.v3, fsnotify, x/sys,
  prometheus/client_golang, cilium/ebpf, internal packages. Anything else
  needs a PR discussion.
- Kernel C: keep to the BPF-verifiable subset, no loops without a constant
  bound, all copies bounded (`DBG_MAX_*`), packed structs mirrored to Go.

## PR checklist

- [ ] `scripts/verify.sh` passes locally
- [ ] New config keys: defaults + validation + docs + example config
- [ ] New kernel struct: Go mirror updated (types.go + decode.go)
- [ ] Policies affected: `dbguard-cli validate-policy` clean
- [ ] Tests for new behavior; integration script updated if user-visible
- [ ] Docs touched (architecture/feature docs, CHANGELOG entry)
