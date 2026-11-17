/* SPDX-License-Identifier: GPL-2.0 */
/* dbguard/src/audit.bpf.c - query auditing
 *
 * One uprobe per database entry point captures the raw SQL string the
 * moment a server process accepts it, before any result rows exist:
 *
 *   engine    symbol                   SQL argument
 *   --------  -----------------------  ------------------------------
 *   postgres  exec_simple_query        arg1 (simple-protocol query)
 *   postgres  pg_parse_query           arg1 (raw_query)
 *   mysql     dispatch_command         arg3 (char *query)
 *
 * Every capture flows through submit_query(): reserve a dbg_query_event
 * ringbuf record, zero it, fill the shared header, copy the SQL with
 * bpf_probe_read_user_str, stamp the process comm, and - when
 * config_map.pii_prescan is set - run the bounded kernel PII pre-scan from
 * dbguard/pii.h whose DBG_QF_* bits user space mirrors (internal/ebpf).
 *
 * Captures are gated on target_pids (pid -> 1), written by the manager from
 * the configured DB process list, so unrelated processes never generate
 * query events.
 */
#include <linux/bpf.h>

#include "dbguard/common.h"
#include "bpf_tracing.h"
#include "dbguard/pii.h"
#include "dbguard/min_compat.h"	/* struct sock + DBG_CORE_READ for the peer hook */

#ifndef AF_INET
#define AF_INET 2
#endif

/* ---- maps ---------------------------------------------------------------
 * events      16 MiB ring buffer shared with the Go reader (manager.go)
 * config_map  single-entry array holding struct dbg_config (key 0)
 * target_pids audited DB process ids, maintained by Manager.UpdateTargets
 */
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
	__type(key, __u32);		/* tgid of the DB server process */
	__type(value, __u8);		/* 1 = audited                   */
} target_pids SEC(".maps");

/* peer_by_tgid correlates a DB backend's client socket tuple to the backend
 * tgid. The SQL uprobe (pg_parse_query / dispatch_command) has NO socket
 * context, so without this the query event carries no client IP and user space
 * cannot resolve its Cilium security identity. A kprobe on tcp_recvmsg runs in
 * the backend's own context right before it parses the query, and records the
 * tuple here; submit_query() then stamps it onto every query event. */
struct dbg_peer {
	__be32 client_v4;	/* remote endpoint = client (skc_daddr),     net order */
	__be32 server_v4;	/* local  endpoint = server (skc_rcv_saddr), net order */
	__u16  client_port;	/* host order */
	__u16  server_port;	/* host order */
	__u32  family;		/* AF_INET (IPv6 backends not correlated yet) */
};

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);		/* backend tgid */
	__type(value, struct dbg_peer);
} peer_by_tgid SEC(".maps");

/* ---- shared submit path --------------------------------------------------
 * submit_query() is inlined into every uprobe handler. ctx is kept in the
 * signature so future engines can enrich events with packet context from
 * the probe frame without changing every call site.
 */
static __always_inline void submit_query(void *ctx, const char *sql,
					 __u32 engine)
{
	struct dbg_config *cfg;
	struct dbg_query_event *e;
	long r0;
	__u32 key = 0;
	__u32 tgid;

	(void)ctx;

	if (!sql)
		return;

	/* Audit gate. A DB server forks a NEW backend process per client
	 * connection (PostgreSQL) or uses per-connection threads (MySQL), so the
	 * specific tgid handling a query is usually NOT one of the long-lived PIDs
	 * discovered at startup. The uprobe is already scoped to the DB binary, so
	 * accept the query when either the exact tgid is registered OR a wildcard
	 * sentinel (key 0 - never a real userspace tgid) is present, which
	 * userspace sets to mean "audit every backend of this DB binary". Without
	 * this, every fresh `psql -c`/new-connection query is dropped in-kernel and
	 * SQLi/PII never fire. */
	tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	{
		__u32 wildcard = 0;
		if (!bpf_map_lookup_elem(&target_pids, &tgid) &&
		    !bpf_map_lookup_elem(&target_pids, &wildcard))
			return;
	}

	cfg = bpf_map_lookup_elem(&config_map, &key);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;		/* ringbuf full: drop quietly */
	__builtin_memset(e, 0, sizeof(*e));

	dbg_fill_hdr(&e->hdr, DBG_EVT_QUERY, DBG_SEV_INFO, DBG_ACT_NONE,
		     engine, 0);

	/* sql: USER pointer into the server process (probe-read string). */
		r0 = bpf_probe_read_user_str(e->sql, sizeof(e->sql), sql);
	if (r0 < 0) {
		bpf_ringbuf_discard(e, 0);
		return;
	}
	
	e->sql_len = r0 > 0 ? (__u32)r0 - 1 : 0;

	dbg_get_comm(e->comm);

	/* Client tuple: correlated from this backend's socket by tgid (the
	 * tcp_recvmsg kprobe below, which runs in the backend before it parses).
	 * The uprobe has no socket, so this is the only place the query event can
	 * learn its client IP - which user-space enrichment needs to resolve the
	 * Cilium identity and to evaluate client/identity policy rules. */
	{
		struct dbg_peer *pp = bpf_map_lookup_elem(&peer_by_tgid, &tgid);

		if (pp) {
			e->family = pp->family;
			__builtin_memcpy(&e->saddr[0], &pp->client_v4,
					 sizeof(pp->client_v4));
			__builtin_memcpy(&e->daddr[0], &pp->server_v4,
					 sizeof(pp->server_v4));
			e->sport = pp->client_port;
			e->dport = pp->server_port;
		}
	}

	
#ifdef DBGUARD_KERNEL_PII_PRESCAN
	if (cfg && cfg->pii_prescan)
		{ __typeof__(e->flags) dbg_fl = e->flags; dbg_scan_pii(e->sql, &dbg_fl); e->flags = dbg_fl; }
#else
	(void)cfg;
#endif

	bpf_ringbuf_submit(e, 0);
}

/* ---- PostgreSQL ---------------------------------------------------------- */

/* Hook: uprobe on exec_simple_query.
 * void exec_simple_query(const char *query_string)
 * Fires once per simple-protocol ('Q') message on the PostgreSQL backend. */
SEC("uprobe")
int uprobe_pg_simple(struct pt_regs *ctx)
{
	const char *sql = (const char *)PT_REGS_PARM1(ctx);

	submit_query(ctx, sql, DBG_ENG_POSTGRES);
	return 0;
}

/* Hook: uprobe on pg_parse_query.
 * List *pg_parse_query(const char *raw_query, ...)
 * Covers extended-protocol Parse ('P') messages and internal parse paths
 * that bypass exec_simple_query (e.g. SPI and prepared statements). */
SEC("uprobe")
int uprobe_pg_parse(struct pt_regs *ctx)
{
	const char *sql = (const char *)PT_REGS_PARM1(ctx);

	submit_query(ctx, sql, DBG_ENG_POSTGRES);
	return 0;
}

/* ---- MySQL / MariaDB ------------------------------------------------------ */

/* Hook: uprobe on dispatch_command.
 * bool dispatch_command(enum enum_server_command command, THD *thd,
 *                       char *packet)
 * The COM_QUERY packet text sits in thd->query in newer servers, but the
 * legacy dispatch_command signature still receives the raw packet buffer as
 * its third argument, which is what we capture. */
SEC("uprobe")
/* MariaDB: dispatch_command(enum_server_command command, THD *thd,
 *                           char *packet, uint packet_length, ...)
 * The query bytes are PARM3 (packet). */
SEC("uprobe")
int uprobe_my_dispatch(struct pt_regs *ctx)
{
	const char *sql = (const char *)PT_REGS_PARM3(ctx);

	submit_query(ctx, sql, DBG_ENG_MYSQL);
	return 0;
}

/* MariaDB/MySQL: mysql_parse(THD *thd, char *rawbuf, uint length, ...).
 * PARM2 is the raw SQL text directly - the most robust capture point, used in
 * preference to dispatch_command when the symbol is present. */
SEC("uprobe")
int uprobe_my_parse(struct pt_regs *ctx)
{
	const char *sql = (const char *)PT_REGS_PARM2(ctx);

	submit_query(ctx, sql, DBG_ENG_MYSQL);
	return 0;
}

/* MySQL 8.0: dispatch_command(THD *thd, const COM_DATA *com_data,
 *                             enum_server_command command)
 * For COM_QUERY the SQL text is com_data->com_query.query. COM_DATA is a
 * union whose first member is struct { const char *query; size_t length; },
 * so the query pointer is at offset 0 of the COM_DATA* in PARM2. We read that
 * pointer with a probe read, then submit the string it points to. */
SEC("uprobe")
int uprobe_my_dispatch80(struct pt_regs *ctx)
{
	void *com_data = (void *)PT_REGS_PARM2(ctx);
	const char *sql = 0;

	if (!com_data)
		return 0;
	/* com_data->com_query.query is at offset 0 */
	if (bpf_probe_read_user(&sql, sizeof(sql), com_data) != 0 || !sql)
		return 0;

	submit_query(ctx, sql, DBG_ENG_MYSQL);
	return 0;
}



/* ---- client-IP correlation ----------------------------------------------- */

/* int tcp_recvmsg(struct sock *sk, struct msghdr *msg, size_t len, ...)
 * Runs in the DB backend's context when it reads the wire bytes of a query,
 * i.e. just before pg_parse_query / dispatch_command. We record the socket's
 * client tuple keyed by the backend tgid so submit_query() can stamp it onto
 * the query event. Scoped to DB server sockets by matching the socket's LOCAL
 * port against the configured PostgreSQL/MySQL port, so this global kprobe does
 * not record a tuple for every process on the host. */
SEC("kprobe/tcp_recvmsg")
int kp_tcp_recvmsg(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	struct dbg_config *cfg_rp;
	__u32 rk = 0;
	__u16 lport;
	__u32 tgid;
	struct dbg_peer p = {};

	if (!sk)
		return 0;

	/* Gate on the socket's LOCAL port matching a configured DB port (a DB
	 * server-side socket). We deliberately do NOT read skc_family: on some
	 * kernels it reads garbage via this struct while the adjacent skc_num and
	 * the v4 address fields (offsets 0/4/12/14) read correctly. The DB socket
	 * is IPv4 here, so the tuple is recorded as AF_INET. */
	lport = DBG_CORE_READ(sk, __sk_common.skc_num);	/* local (server) port, host order */

	cfg_rp = bpf_map_lookup_elem(&config_map, &rk);
	if (!cfg_rp)
		return 0;
	if (lport != cfg_rp->pg_port && lport != cfg_rp->mysql_port)
		return 0;	/* not a DB server-side socket */

	tgid = (__u32)(bpf_get_current_pid_tgid() >> 32);

	p.family      = AF_INET;
	p.client_v4   = DBG_CORE_READ(sk, __sk_common.skc_daddr);     /* remote = client */
	p.server_v4   = DBG_CORE_READ(sk, __sk_common.skc_rcv_saddr); /* local  = server */
	p.client_port = bpf_ntohs(DBG_CORE_READ(sk, __sk_common.skc_dport));
	p.server_port = lport;
	bpf_map_update_elem(&peer_by_tgid, &tgid, &p, BPF_ANY);
	return 0;
}

SEC("license")
char _license[] = DBGUARD_LICENSE;
