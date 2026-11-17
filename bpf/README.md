# DBGuard eBPF layer

Kernel-side programs (CO-RE, self-contained vendored headers - only `clang`
and Linux UAPI headers are needed). Everything here is built by the repo
root Makefile:

```sh
make bpf        # compile bpf/src/*.bpf.c -> build/bpf/*.bpf.o (+ _lsm variants)
```

Requires `clang >= 11` (BPF target) and `llvm-strip`. The Makefile picks
`-D__TARGET_ARCH_x86` / `-D__TARGET_ARCH_arm64` from `uname -m`. The `*_lsm`
objects are the same sources compiled with `-DBGUARD_ENABLE_LSM`, which
turns on the enforcing BPF-LSM hooks (`rids_lsm.bpf.o` has a dedicated
rule; `tenant_guard_lsm.bpf.o` needs the same one-line rule mirrored).

## Object -> program -> hook matrix

| object | program | SEC() section | hook |
|---|---|---|---|
| audit.bpf.o | uprobe_pg_simple / uprobe_pg_parse / uprobe_my_dispatch / uprobe_sqlite_exec / uprobe_sqlite_prepare | uprobe | query symbols of the DB binaries (loader `uprobe_` naming) |
| sqli_firewall.bpf.o | cgroup_egress_sqli | cgroup_skb/egress | cgroup v2 `/sys/fs/cgroup` egress |
| sqli_firewall.bpf.o | xdp_sqi_guard | xdp | XDP on configured interfaces |
| exfil_breaker.bpf.o | kprobe_tcp_sendmsg / kretprobe_tcp_sendmsg | kprobe,kretprobe/tcp_sendmsg | send accounting per socket |
| exfil_breaker.bpf.o | cgroup_egress_exfil | cgroup_skb/egress | quarantine enforcement |
| rids.bpf.o | tp_execve / tp_openat | tracepoint/syscalls/sys_enter_{execve,openat} | syscall tracepoints |
| rids_lsm.bpf.o | bprm_check / lsm_file_open | lsm/bprm_check_security, lsm/file_open | BPF LSM (enforce) |
| conn_anomaly.bpf.o | kp_tcp_v4_connect | kprobe/tcp_v4_connect | connect-rate spike |
| conn_anomaly.bpf.o | krp_inet_csk_accept | kretprobe/inet_csk_accept | accept flood + flow open |
| conn_anomaly.bpf.o | kp_tcp_close | kprobe/tcp_close | flow close |
| conn_anomaly.bpf.o | cgroup_ingress_auth | cgroup_skb/ingress | auth-failure spike |
| lineage.bpf.o | cgroup_egress_lineage | cgroup_skb/egress | query <-> app-route join |
| tenant_guard.bpf.o | tp_openat_tenant | tracepoint/syscalls/sys_enter_openat | cross-tenant report |
| tenant_guard_lsm.bpf.o | lsm_tenant_file_open | lsm/file_open | cross-tenant deny |
| microseg_xdp.bpf.o | xdp_microseg | xdp | identity-aware micro-segmentation |
| microseg_sockmap.bpf.o | stream_parser / stream_verdict / sk_msg_redirect_same | sk_skb/stream_parser, sk_skb/stream_verdict, sk_msg | Cilium sockmap acceleration |

`sk_skb_*` / `sk_msg_*` programs are intentionally left unattached by the Go
loader (`internal/ebpf/loader.go`); the Cilium sockmap orchestrator
(`deploy/cilium/sockmap-enable.yaml`) owns them.

## Kernel requirements

- Linux **5.8+** recommended: `BPF_MAP_TYPE_RINGBUF` is used by every object.
- BTF for CO-RE: `CONFIG_DEBUG_INFO_BTF=y`.
- BPF LSM (only for `*_lsm.bpf.o`): Linux 5.7+, `CONFIG_BPF_LSM=y` and
  `lsm=bpf` appended to the `lsm=` boot parameter.
- Bounded loops: 5.3+ (all loops in these programs are constant-bounded).
- cgroup v2 mounted at `/sys/fs/cgroup` (cgroup_skb attach point).
- XDP: native driver mode preferred, generic fallback is automatic.
- Sockmap: Linux 4.20+ (`SOCKHASH` + `bpf_msg_redirect_hash`).
- Privileges: root, or `CAP_BPF`+`CAP_PERFMON` (plus `CAP_SYS_ADMIN` on
  pre-5.8 kernels; `CAP_MAC_ADMIN` for LSM deny decisions).

## bpftool verification

```sh
bpftool prog list                    # loaded programs (names as in the matrix)
bpftool map dump name config_map     # pg_port/mysql_port (host order), flags
bpftool map dump name conn_stats     # per-cpu counters (one value per CPU)
bpftool map dump name active_conns   # live DB conns per client IP
bpftool map dump name client_policy  # LPM entries (prefixlen/addr -> bits)
bpftool net show dev eth0            # xdp attachment state
```

## Troubleshooting

- **Verifier failures**: raise the manager's log level to see the full
  verifier log, or reproduce by hand with
  `bpftool prog load build/bpf/<obj>.bpf.o` - the trailing log lines name
  the offending instruction.
- **Stale pins**: after an unclean daemon exit, pinned maps/links under
  `/sys/fs/bpf/dbguard` can block a reload (`EEXIST`). Clean them with
  `rm -rf /sys/fs/bpf/dbguard` before restarting.
- **Attach errors**: cgroup_skb hooks need cgroup v2; `lsm/*` sections need
  the `lsm=bpf` boot parameter; XDP needs the interface up (generic mode on
  veth).
- **aarch64**: no source changes needed - the Makefile exports
  `__TARGET_ARCH_arm64` and `bpf_tracing.h` supplies the arm64 `PT_REGS_*`
  accessors. Some arm64 kernel builds omit `CONFIG_BPF_LSM`, so only the
  tracepoint/kprobe/cgroup objects will load there.
