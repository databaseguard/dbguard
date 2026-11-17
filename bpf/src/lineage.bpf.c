/* SPDX-License-Identifier: GPL-2.0 */
/* dbguard/src/lineage.bpf.c - dual-sided context matcher (kernel side).
 *
 * Joins database queries back to the application that issued them, in the
 * kernel, using the socket cookie as the join key. The userspace contract:
 *
 *   1. internal/lineage/tagger.go (RouteTagger) knows the route of each
 *      application process (k8s pod annotations / env) and populates
 *      route_by_pid[pid] = "<route>" (NUL-padded, <= 127 chars).
 *   2. On the first outbound SYN of a socket this program records the app
 *      origin in app_ctx[sock_cookie] = { pid, cgroup, seen_ns }.
 *   3. Later query packets on the same socket are joined back through
 *      bpf_get_socket_cookie() and the recorded origin; the resolved route
 *      is attached to the emitted DBG_EVT_LINEAGE event.
 *
 * Verdict flags carried by the event:
 *   flags = 0  clean join (route resolved)          -> DBG_SEV_INFO
 *   flags = 1  query on a socket with no recorded
 *              app origin (unknown origin /
 *              hijack-suspected)                    -> DBG_SEV_MEDIUM
 *   flags = 2  origin known but the pid carries no
 *              route tag (unmatched-route)          -> DBG_SEV_MEDIUM
 *
 * The cgroup_skb/egress hook only ever OBSERVES: it returns SK_PASS on
 * every path. Wire sniffing matches sqli_firewall.bpf.c (PG 'Q', MySQL
 * COM_QUERY 0x03).
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

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

/* App origin per socket, keyed by bpf_get_socket_cookie(). Written once on
 * the tracked SYN, read on every query packet of the same socket. */
struct dbg_app_ctx {
	__u32 pid;		/* originating application tgid        */
	__u32 cgroup_lo;	/* low 32 bits of the cgroup id        */
	__u64 seen_ns;		/* ktime of the recording SYN          */
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);		/* sock_cookie                */
	__type(value, struct dbg_app_ctx);
} app_ctx SEC(".maps");

/* pid -> route tag (e.g. "checkout/prod/eu"). Populated by the userspace
 * RouteTagger; NUL-padded char[DBG_MAX_ROUTE] values. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);		/* tgid                       */
	__type(value, char[DBG_MAX_ROUTE]);
} route_by_pid SEC(".maps");

/* Per-CPU counters, indexed by the enum below (bpftool map dump friendly). */
enum {
	LINEAGE_SYNS = 0,	/* app origins recorded on SYN           */
	LINEAGE_QUERIES,	/* query payloads joined                 */
	LINEAGE_UNKNOWN,	/* flags=1 events (no recorded origin)   */
	LINEAGE_UNROUTED,	/* flags=2 events (pid without a tag)    */
	LINEAGE_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, LINEAGE_MAX);
	__type(key, __u32);
	__type(value, __u64);
} lineage_stats SEC(".maps");

static __always_inline void lineage_stat_bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&lineage_stats, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

/* ---- packet parsing -----------------------------------------------------------
 * dbg_flow4 describes a validated Ethernet(+VLAN)/IPv4/TCP packet. Ports are
 * host order (bpf_ntohs applied); only the destination port is used here.
 */
struct dbg_flow4 {
	__u16 sport;
	__u16 dport;
	__u8 doff;		/* TCP data offset, 32-bit words */
	struct tcphdr *tcp;
};

static __always_inline int dbg_parse_tcp4(void *data, void *data_end,
					  struct dbg_flow4 *fl)
{
	struct ethhdr *eth = data;
	struct dbg_vlan_hdr *vlan;
	struct iphdr *ip;
	__u8 *ipb;
	struct tcphdr *tcp;
	__u64 hlen = sizeof(*eth);
	__u16 proto;
	__u32 ihl;

	if ((void *)(eth + 1) > data_end)
		return -1;
	proto = bpf_ntohs(eth->h_proto);

	/* One optional 802.1Q tag (same handling as sqli_firewall). */
	if (proto == ETH_P_8021Q) {
		vlan = (void *)eth + hlen;
		if ((void *)(vlan + 1) > data_end)
			return -1;
		proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
		hlen += sizeof(*vlan);
	}
	if (proto != ETH_P_IP)
		return -1;

	ip = (void *)eth + hlen;
	if ((void *)(ip + 1) > data_end)
		return -1;
	ipb = (__u8 *)ip;
	if ((ipb[0] >> 4) != 4)
		return -1;
	ihl = ipb[0] & 0x0f;
	if (ihl < 5)
		return -1;
	if (ip->protocol != IPPROTO_TCP)
		return -1;

	tcp = (void *)ip + (__u64)ihl * 4;
	if ((void *)(tcp + 1) > data_end)	/* covers the fixed 20B header */
		return -1;
	fl->tcp = tcp;
	fl->sport = bpf_ntohs(tcp->source);	/* wire -> host order */
	fl->dport = bpf_ntohs(tcp->dest);
	fl->doff = (((const __u8 *)tcp)[12] >> 4) & 0xf;
	if (fl->doff < 5)
		return -1;
	return 0;
}

/* ---- protocol sniffing ----------------------------------------------------
 * Same wire shapes as sqli_firewall.bpf.c: PostgreSQL 'Q' (simple query)
 * carries a big-endian length that counts itself but not the type byte;
 * MySQL COM_QUERY carries a 3-byte little-endian length, sequence byte and
 * command byte 0x03. Returns 1 when the payload is a query message.
 */
static __always_inline int dbg_sniff_query(__u32 engine, const char *p,
					   __u32 plen)
{
	__u32 mlen;

	if (plen < 5)
		return 0;
	if (engine == DBG_ENG_POSTGRES) {
		if (p[0] != 'Q')
			return 0;
		mlen = ((__u32)(__u8)p[1] << 24) | ((__u32)(__u8)p[2] << 16) |
		       ((__u32)(__u8)p[3] << 8) | (__u32)(__u8)p[4];
		if (mlen < 5 || mlen > 65535)
			return 0;
		return 1;
	}
	if (engine == DBG_ENG_MYSQL) {
		mlen = (__u32)(__u8)p[0] | ((__u32)(__u8)p[1] << 8) |
		       ((__u32)(__u8)p[2] << 16);
		if ((__u8)p[4] != 0x03)
			return 0;
		if (mlen < 1 || mlen > 16384)
			return 0;
		return 1;
	}
	return 0;
}

/* ---- event emission --------------------------------------------------------- */

static __always_inline void lineage_emit(__u32 engine, __u64 cookie,
					 __u32 app_pid, const char *route,
					 __u32 flags)
{
	struct dbg_lineage_event *e;
	__u32 i;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	__builtin_memset(e, 0, sizeof(*e));
	dbg_fill_hdr(&e->hdr, DBG_EVT_LINEAGE,
		     flags ? DBG_SEV_MEDIUM : DBG_SEV_INFO, DBG_ACT_NONE,
		     engine, cookie);
	if (route) {
		for (i = 0; i < DBG_MAX_ROUTE - 1; i++) {	/* const bound */
			char c = route[i];

			if (c == '\0')
				break;
			e->route[i] = c;
		}
	}
	e->sock_cookie = cookie;
	e->app_pid = app_pid;
	e->flags = flags;
	bpf_ringbuf_submit(e, 0);
}

/* ---- cgroup_skb/egress -------------------------------------------------------- */

SEC("cgroup_skb/egress")
int cgroup_egress_lineage(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct dbg_config *cfg;
	struct dbg_flow4 fl;
	struct dbg_app_ctx *app;
	char *route = 0;	/* 0 = no route (unknown origin / unrouted) */
	char *p;
	__u32 plen;
	__u32 pid, cgroup_lo;
	__u32 key = 0;
	__u32 engine;
	__u32 flags = 0;
	__u64 cookie;

	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg || !cfg->lineage_enabled)
		return SK_PASS;
	if (dbg_parse_tcp4(data, data_end, &fl))
		return SK_PASS;

	/* only the DB wire ports (config ports are host order) */
	if (fl.dport != cfg->pg_port && fl.dport != cfg->mysql_port)
		return SK_PASS;
	engine = (fl.dport == cfg->pg_port) ? DBG_ENG_POSTGRES : DBG_ENG_MYSQL;

	cookie = bpf_get_socket_cookie(skb);
	pid = (__u32)(bpf_get_current_pid_tgid() >> 32);
	cgroup_lo = (__u32)bpf_get_current_cgroup_id();

	/* TCP control flags live in byte 13 of the header; TH_SYN = 0x02.
	 * The first outbound SYN pins the app origin for this socket. */
	if (((const __u8 *)fl.tcp)[13] & 0x02) {
		struct dbg_app_ctx fresh;

		__builtin_memset(&fresh, 0, sizeof(fresh));
		fresh.pid = pid;
		fresh.cgroup_lo = cgroup_lo;
		fresh.seen_ns = bpf_ktime_get_ns();
		bpf_map_update_elem(&app_ctx, &cookie, &fresh, BPF_ANY);
		lineage_stat_bump(LINEAGE_SYNS);
		return SK_PASS;
	}

	/* sniff a query payload (PG 'Q' / MySQL COM_QUERY) */
	p = (char *)fl.tcp + (__u32)fl.doff * 4;
	if ((void *)p >= data_end)
		return SK_PASS;
	plen = (__u32)((char *)data_end - p);
	if ((void *)(p + 5) > data_end)	/* verifier: keep p[0..4] in packet bounds */
		plen = 0;
	if (!dbg_sniff_query(engine, p, plen))
		return SK_PASS;
	lineage_stat_bump(LINEAGE_QUERIES);

	app = bpf_map_lookup_elem(&app_ctx, &cookie);
	if (!app) {
		/* unknown origin: no tracked SYN on this socket */
		lineage_emit(engine, cookie, 0, 0, 1);
		lineage_stat_bump(LINEAGE_UNKNOWN);
		return SK_PASS;
	}

	route = bpf_map_lookup_elem(&route_by_pid, &app->pid);
	if (!route) {
		flags = 2;	/* origin known, no route tag for this pid */
		lineage_stat_bump(LINEAGE_UNROUTED);
	}
	lineage_emit(engine, cookie, app->pid, route, flags);
	return SK_PASS;
}

SEC("license")
char _license[] = DBGUARD_LICENSE;
