/* SPDX-License-Identifier: GPL-2.0 */
/* dbguard/src/tenant_guard.bpf.c - multi-tenant isolation guard.
 *
 * Keeps tenants of a shared cluster from touching each other's files.
 * Tenancy is resolved from the cgroup: the manager populates
 * tenant_by_cgroup[cgroup_id] = tenant_id, and registers the path prefixes
 * owned by each tenant in path_owner["/prefix"] = tenant_id.
 *
 * Two hooks share the matching logic in this file:
 *
 *   tracepoint/syscalls/sys_enter_openat  tp_openat_tenant      report only
 *   lsm/file_open                         lsm_tenant_file_open  enforce
 *
 * The tracepoint always runs and is ALERT-ONLY (it cannot deny anything);
 * the LSM hook is compiled into the second object of this source (make bpf
 * builds tenant_guard_lsm.bpf.o with -DBGUARD_ENABLE_LSM) and additionally
 * denies a cross-tenant open with -EACCES unless config.rids_alert_only
 * puts the agent in observe-only mode.
 *
 * Matching: a longest-prefix approximation over path_owner. Constant
 * bounded work - at most 8 candidate lookups of the first 63 chars each:
 * the full path first, then the path truncated at successive '/'
 * boundaries (dropping one trailing component per step). Candidates are
 * probed longest-first, so the first hit is the longest match.
 */
#include <linux/bpf.h>

#include "dbguard/common.h"
#include "bpf_tracing.h"
#include "dbguard/min_compat.h"

/* ---- maps --------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dbg_config);
} config_map SEC(".maps");

/* cgroup -> tenant. Populated by the manager from the tenant registry;
 * absence means "unmanaged cgroup", which is never enforced against. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);		/* cgroup id                  */
	__type(value, __u32);		/* tenant id, 0 = unset       */
} tenant_by_cgroup SEC(".maps");

/* Per-tenant allowed path prefixes (informational mirror of the policy
 * file; the guard matches against path_owner below). */
struct dbg_prefixes {
	char p[DBG_MAX_PREFIXES][DBG_PREFIX_LEN];	/* 8 x 64, NUL-padded */
	__u8 n;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);		/* tenant id                  */
	__type(value, struct dbg_prefixes);
} allowed_paths SEC(".maps");

/* NUL-padded [64] path prefix -> owning tenant id. Populated by the
 * manager (Manager.UpdatePathOwners). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 512);
	__type(key, char[DBG_PREFIX_LEN]);	/* e.g. "/var/lib/postgresql" */
	__type(value, __u32);
} path_owner SEC(".maps");

/* Per-CPU counters, indexed by the enum below (bpftool map dump friendly). */
enum {
	TENANT_OPENS = 0,	/* opens by tagged tenants screened      */
	TENANT_VIOLATIONS,	/* cross-tenant opens detected           */
	TENANT_LSM_DENIES,	/* opens denied by the LSM hook          */
	TENANT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, TENANT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} tenant_stats SEC(".maps");

static __always_inline void tenant_stat_bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&tenant_stats, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}


static __always_inline __u32 tenant_path_owner(const char *path,
                           __u32 path_len)
{
    char key[DBG_PREFIX_LEN];
    __u32 *owner;
    __u32 cut, j, start;

    if (!path || path_len == 0)
        return 0;

    start = path_len;
    if (start > DBG_PREFIX_LEN - 1)
        start = DBG_PREFIX_LEN - 1;

    for (cut = start; cut >= 1; cut--) {
        for (j = 0; j < DBG_PREFIX_LEN; j++)    /* const bound: 64 */
            ((volatile unsigned char *)key)[j] =
                path[j] & (__u8)(((__u32)(j - cut)) >> 8);
        owner = bpf_map_lookup_elem(&path_owner, key);
        if (owner)
            return *owner;
    }
    return 0;
}

/* Shared violation reporting: emits a DBG_EVT_TENANT record. verdict is
 * DBG_ACT_ALERT (report) or DBG_ACT_QUARANTINE (LSM deny). */
static __always_inline void tenant_report(const char *path, __u32 caller,
					  __u32 owner, __u32 verdict)
{
	struct dbg_tenant_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	__builtin_memset(e, 0, sizeof(*e));
	dbg_fill_hdr(&e->hdr, DBG_EVT_TENANT, DBG_SEV_HIGH, verdict,
		     DBG_ENG_UNKNOWN, 0);
	__builtin_memcpy(e->path, path, DBG_MAX_PATH);
	e->tenant_id = caller;
	e->owner_tenant = owner;
	e->verdict = verdict;
	bpf_ringbuf_submit(e, 0);
}

/* ---- tracepoint: sys_enter_openat (alert-only) ------------------------------- */

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat_tenant(struct dbg_trace_enter *ctx)
{
	char path[DBG_MAX_PATH];
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u32 *caller;
	__u32 owner;
	__u32 path_len;

	/* 0 = unknown tenant: the manager has not tagged this cgroup */
	caller = bpf_map_lookup_elem(&tenant_by_cgroup, &cgroup_id);
	if (!caller)
		return 0;
	tenant_stat_bump(TENANT_OPENS);

	__builtin_memset(path, 0, sizeof(path));
	/* args[1] = pathname (const char *), a USER pointer */
	if (ctx->args[1])
		bpf_probe_read_user_str(path, sizeof(path),
					(const void *)ctx->args[1]);
	path_len = dbg_strnlen(path, DBG_MAX_PATH);

	owner = tenant_path_owner(path, path_len);
	if (!owner || owner == *caller)
		return 0;

	/* cross-tenant open: report only; the LSM build below denies */
	tenant_stat_bump(TENANT_VIOLATIONS);
	tenant_report(path, *caller, owner, DBG_ACT_ALERT);
	return 0;
}

/* ---- BPF LSM (built into tenant_guard_lsm.bpf.o with -DBGUARD_ENABLE_LSM) ---- */
#ifdef DBGUARD_ENABLE_LSM

/* Same matching as the tracepoint, but enforcing: a cross-tenant open is
 * denied with -EACCES (verdict DBG_ACT_QUARANTINE) unless
 * config.rids_alert_only puts the agent in observe-only mode. */
SEC("lsm/file_open")
int lsm_tenant_file_open(struct dbg_file *file)
{
	struct dbg_config *cfg;
	char path[DBG_MAX_PATH];
	__u64 cgroup_id = bpf_get_current_cgroup_id();
	__u32 *caller;
	__u32 owner;
	__u32 key = 0;
	int n;

	if (!file)
		return 0;
	caller = bpf_map_lookup_elem(&tenant_by_cgroup, &cgroup_id);
	if (!caller)
		return 0;

	__builtin_memset(path, 0, sizeof(path));
	/* reconstruct the path from the dentry chain (CO-RE reads) */
	n = dbg_read_path(file, path, (int)sizeof(path));
	if (n <= 0)
		return 0;

	owner = tenant_path_owner(path, (__u32)n);
	if (!owner || owner == *caller)
		return 0;
	tenant_stat_bump(TENANT_VIOLATIONS);

	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (cfg && !cfg->rids_alert_only) {
		/* deny: the event's verdict records the enforcement taken */
		tenant_stat_bump(TENANT_LSM_DENIES);
		tenant_report(path, *caller, owner, DBG_ACT_QUARANTINE);
		return -EACCES;
	}
	/* alert-only mode: report and allow */
	tenant_report(path, *caller, owner, DBG_ACT_ALERT);
	return 0;
}

#endif /* DBGUARD_ENABLE_LSM */

SEC("license")
char _license[] = DBGUARD_LICENSE;
