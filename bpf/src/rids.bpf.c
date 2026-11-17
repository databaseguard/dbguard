/* SPDX-License-Identifier: GPL-2.0 */
/* dbguard/src/rids.bpf.c - runtime intrusion detection.
 *
 * Watches process activity of the database workloads themselves:
 *
 *   tracepoint/syscalls/sys_enter_execve  tp_execve      audit + block decision
 *   tracepoint/syscalls/sys_enter_openat  tp_openat      protected-file auditing
 *   lsm/bprm_check_security               bprm_check     enforce (kill exec)
 *   lsm/file_open                         lsm_file_open  enforce (deny write)
 *
 * The tracepoints always run; the LSM hooks are compiled into the second
 * object of this source (make bpf builds rids_lsm.bpf.o with
 * -DBGUARD_ENABLE_LSM) and additionally enforce: blocked executables are
 * denied with -EPERM, protected files are denied for writes with -EACCES,
 * and quarantined tasks are frozen out of both paths.
 *
 * Path matching: blocked_paths / protected_prefixes are hash maps keyed by
 * NUL-padded path prefixes (<= 63 chars, written by Manager.UpdateBlockedPaths).
 * In-kernel matching walks the captured path and checks the map at every '/'
 * boundary - with and without the trailing slash - plus the exact path.
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

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u32);		/* tgid */
	__type(value, __u8);		/* 1 = monitored DB process */
} target_pids SEC(".maps");

/* NUL-padded [64] path keys -> 1. Populated by userspace. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, char[DBG_PREFIX_LEN]);	/* e.g. "/usr/bin/nc" */
	__type(value, __u8);
} blocked_paths SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, char[DBG_PREFIX_LEN]);	/* e.g. "/etc/dbguard" */
	__type(value, __u8);
} protected_prefixes SEC(".maps");

/* Frozen tasks: tgid -> expiry (ktime ns). While a task is listed and the
 * expiry is in the future, LSM hooks deny execution and file opens. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);		/* tgid */
	__type(value, __u64);		/* expiry ns */
} quarantined_tasks SEC(".maps");

enum {
	RIDS_EXEC_SEEN = 0,	/* execs observed behind the gate        */
	RIDS_EXEC_BLOCKED,	/* execs matching blocked_paths          */
	RIDS_FILE_BLOCKED,	/* protected writes denied (LSM)         */
	RIDS_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, RIDS_MAX);
	__type(key, __u32);
	__type(value, __u64);
} rids_stats SEC(".maps");

static __always_inline void rids_stat_bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&rids_stats, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

/* ---- helpers -------------------------------------------------------------- */

/* Gate: only monitored DB processes (target_pids or the well-known server
 * comm names) generate RIDS events, keeping noise off the ring buffer. */
static __always_inline int rids_gate(__u32 tgid)
{
	char comm[DBG_MAX_COMM];

	if (bpf_map_lookup_elem(&target_pids, &tgid))
		return 1;
	dbg_get_comm(comm);
	if (dbg_contains_ci(comm, DBG_MAX_COMM, "postgres", 8) ||
	    dbg_contains_ci(comm, DBG_MAX_COMM, "mysqld", 6) ||
	    dbg_contains_ci(comm, DBG_MAX_COMM, "mariadbd", 8) ||
	    dbg_contains_ci(comm, DBG_MAX_COMM, "sqlite3", 7))
		return 1;
	return 0;
}

static __always_inline int rids_path_match(void *map, const char *path)
{
 char key[DBG_PREFIX_LEN];
 __u8 *hit;
 __u32 i;
 int saw_end = 0;

 __builtin_memset(key, 0, sizeof(key));
 for (i = 0; i < DBG_PREFIX_LEN; i++) {  /* constant bound: 64 */
         char c = path[i];

         if (c == '\0') {
                 saw_end = 1;
                 break;
         }
         key[i] = c;
         if (c != '/')
                 continue;
         key[i] = '\0';                 /* prefix without slash */
         hit = bpf_map_lookup_elem(map, key);
         if (hit)
                 return 1;
         key[i] = '/';                   /* prefix with slash */
         hit = bpf_map_lookup_elem(map, key);
         if (hit)
                 return 1;
 }
 if (saw_end) {
         hit = bpf_map_lookup_elem(map, key);    /* exact path */
         if (hit)
                 return 1;
 }
 return 0;
}

/* ---- tracepoints ----------------------------------------------------------- */

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_execve(struct dbg_trace_enter *ctx)
{
	struct dbg_config *cfg __attribute__((unused));
	struct dbg_exec_event *e;
	char tmp[128];
	char *argv_ptrs[2];
	__u32 key = 0;
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	__u32 verdict = DBG_ACT_ALERT;
	__u32 pos = 0;
	__u32 i;
	int blocked = 0;
	int r0;

	if (!rids_gate(tgid))
		return 0;
	cfg = bpf_map_lookup_elem(&config_map, &key);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	dbg_fill_hdr(&e->hdr, DBG_EVT_EXEC, DBG_SEV_CRITICAL, DBG_ACT_ALERT,
		     DBG_ENG_UNKNOWN, 0);
	dbg_get_comm(e->comm);
	rids_stat_bump(RIDS_EXEC_SEEN);

	/* args[0] = filename (const char *), a USER pointer */
	if (ctx->args[0])
		bpf_probe_read_user_str(e->path, sizeof(e->path),
					(const void *)ctx->args[0]);

	/* args[1] = argv (const char *const *): capture the first two
	 * pointers and read each string into the event's argv field. */
	e->argc = 0;
	if (ctx->args[1] &&
	    bpf_probe_read_user(argv_ptrs, sizeof(argv_ptrs),
				(const void *)ctx->args[1]) == 0 &&
	    argv_ptrs[0]) {
		r0 = bpf_probe_read_user_str(e->argv, sizeof(e->argv),
					     argv_ptrs[0]);
		if (r0 > 0) {
			e->argc = 1;
			pos = (__u32)r0 - 1;	/* NUL slot of argv0 */
			if (pos > DBG_MAX_ARGSTR - 1)
				pos = DBG_MAX_ARGSTR - 1;
		}
	}
	if (e->argc == 1 && argv_ptrs[1]) {
		__u32 len1;

		__builtin_memset(tmp, 0, sizeof(tmp));
		r0 = bpf_probe_read_user_str(tmp, sizeof(tmp), argv_ptrs[1]);
		if (r0 > 1 && pos < DBG_MAX_ARGSTR - 2) {
			len1 = (__u32)r0 - 1;
			if (len1 > DBG_MAX_ARGSTR - 2 - pos)
				len1 = DBG_MAX_ARGSTR - 2 - pos;
			/* verifier: the append loop stores at (argv + pos + i) and
			 * the verifier bounds the two variable parts independently;
			 * capping pos at 127 keeps base + pos + i inside the event
			 * for every i < 128. argv[0] longer than 127 bytes is
			 * display-truncated when argv[1] exists. */
			if (pos > 127)
				pos = 127;
			e->argv[pos] = ' ';
			pos++;
			for (i = 0; i < 128; i++) {	/* constant bound */
				if ((__u32)pos + (__u32)i >= sizeof(e->argv))
					break;
				if (i >= len1)
					break;
				e->argv[(__u32)(pos + i) & (__u32)(sizeof(e->argv) - 1)] = tmp[i];
			}
			e->argc = 2;
		}
	}

	/* verdict is advisory here; the LSM build below enforces it */
	if (e->path[0] && rids_path_match(&blocked_paths, e->path)) {
		blocked = 1;
		rids_stat_bump(RIDS_EXEC_BLOCKED);
	}
	if (blocked && cfg && !cfg->rids_alert_only)
		verdict = DBG_ACT_KILL;
	e->verdict = verdict;
	e->hdr.action = verdict;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_openat(struct dbg_trace_enter *ctx)
{
	struct dbg_config *cfg __attribute__((unused));
	struct dbg_file_event *e;
	__u32 key = 0;
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	int hit;

	if (!rids_gate(tgid))
		return 0;
	cfg = bpf_map_lookup_elem(&config_map, &key);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	dbg_fill_hdr(&e->hdr, DBG_EVT_FILE, DBG_SEV_HIGH, DBG_ACT_ALERT,
		     DBG_ENG_UNKNOWN, 0);
	dbg_get_comm(e->comm);

	/* args[1] = pathname (const char *), a USER pointer */
	if (ctx->args[1])
		bpf_probe_read_user_str(e->path, sizeof(e->path),
					(const void *)ctx->args[1]);

	/* args[2] = openat(2) flags; O_ACCMODE bits reveal the requested
	 * mode. The tracepoint cannot see the final fd write mode (the open
	 * may still fail), so user space refines the verdict from the
	 * flags and the fd table. */
	e->flags = (__u32)ctx->args[2];

	hit = e->path[0] && rids_path_match(&protected_prefixes, e->path);
	if (hit) {
		e->verdict = DBG_ACT_ALERT;
		e->hdr.action = DBG_ACT_ALERT;
		bpf_ringbuf_submit(e, 0);
		return 0;
	}
	bpf_ringbuf_discard(e, 0);
	return 0;
}

/* ---- BPF LSM (built into rids_lsm.bpf.o with -DBGUARD_ENABLE_LSM) --------- */
#ifdef DBGUARD_ENABLE_LSM

SEC("lsm/bprm_check_security")
int bprm_check(struct dbg_linux_binprm *bprm)
{
	struct dbg_config *cfg __attribute__((unused));
	struct dbg_exec_event *e;
	const char *fn = NULL;
	__u32 key = 0;
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	__u64 *qexp;
	__u64 now;
	int blocked;

	if (!bprm)
		return 0;
	if (!rids_gate(tgid))
		return 0;

	/* quarantined (frozen) tasks may not start new programs at all */
	now = bpf_ktime_get_ns();
	qexp = bpf_map_lookup_elem(&quarantined_tasks, &tgid);
	if (qexp && *qexp > now)
		return -EPERM;

	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (cfg && cfg->rids_alert_only)
		return 0;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	dbg_fill_hdr(&e->hdr, DBG_EVT_EXEC, DBG_SEV_CRITICAL, DBG_ACT_KILL,
		     DBG_ENG_UNKNOWN, 0);
	dbg_get_comm(e->comm);

	/* bprm->filename is a KERNEL pointer with CO-RE relocation */
	if (DBG_CORE_READ_INTO(&fn, bprm, filename) != 0 || !fn) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	bpf_probe_read_kernel_str(e->path, sizeof(e->path), fn);

	blocked = e->path[0] && rids_path_match(&blocked_paths, e->path);
	if (!blocked) {
		bpf_ringbuf_discard(e, 0);
		return 0;
	}
	rids_stat_bump(RIDS_EXEC_BLOCKED);
	e->verdict = DBG_ACT_KILL;
	e->hdr.action = DBG_ACT_KILL;
	bpf_ringbuf_submit(e, 0);
	return -EPERM;
}

SEC("lsm/file_open")
int lsm_file_open(struct dbg_file *file)
{
	struct dbg_config *cfg __attribute__((unused));
	struct dbg_file_event *e;
	__u32 fmode = 0;
	__u32 key = 0;
	__u32 tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	__u64 *qexp;
	__u64 now;
	int hit;

	if (!file)
		return 0;
	if (!rids_gate(tgid))
		return 0;

	/* quarantined tasks: deny everything, no event spam */
	now = bpf_ktime_get_ns();
	qexp = bpf_map_lookup_elem(&quarantined_tasks, &tgid);
	if (qexp && *qexp > now)
		return -EACCES;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	dbg_fill_hdr(&e->hdr, DBG_EVT_FILE, DBG_SEV_HIGH, DBG_ACT_ALERT,
		     DBG_ENG_UNKNOWN, 0);
	dbg_get_comm(e->comm);

	/* reconstruct the path from the dentry chain (CO-RE reads) */
	dbg_read_path(file, e->path, (int)sizeof(e->path));
	fmode = DBG_CORE_READ(file, f_mode);	/* FMODE_WRITE is 0x2 */
	e->flags = fmode;

	hit = e->path[0] && rids_path_match(&protected_prefixes, e->path);
	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (hit && (fmode & 0x2) && cfg && !cfg->rids_alert_only) {
		/* write-mode open of a protected prefix: deny */
		rids_stat_bump(RIDS_FILE_BLOCKED);
		e->verdict = DBG_ACT_QUARANTINE;
		e->hdr.action = DBG_ACT_QUARANTINE;
		bpf_ringbuf_submit(e, 0);
		return -EACCES;
	}
	if (hit) {
		e->verdict = DBG_ACT_ALERT;
		e->hdr.action = DBG_ACT_ALERT;
		bpf_ringbuf_submit(e, 0);
		return 0;
	}
	bpf_ringbuf_discard(e, 0);
	return 0;
}

#endif /* DBGUARD_ENABLE_LSM */

SEC("license")
char _license[] = DBGUARD_LICENSE;
