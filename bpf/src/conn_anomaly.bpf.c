/* SPDX-License-Identifier: GPL-2.0 */
/* dbguard/src/conn_anomaly.bpf.c - connection-pool anomaly detection (kernel side).
 *
 * Watches the shape of TCP traffic towards the configured database ports
 * and raises three kernel-side anomaly alerts:
 *
 *   kprobe/tcp_v4_connect      kp_tcp_v4_connect    connect-rate spike
 *   kretprobe/inet_csk_accept  krp_inet_csk_accept  live-conn flood per
 *                                               client + flow accounting
 *   kprobe/tcp_close           kp_tcp_close         flow accounting (close)
 *   cgroup_skb/ingress         cgroup_ingress_auth  auth-failure spike
 *
 * Thresholds (static kernel-side, tuned further in the manager):
 *   >100 connects per second to a DB port       -> DBG_ALC_CONN_SPIKE MEDIUM
 *   >200 concurrently live conns per client IP  -> DBG_ALC_CONN_SPIKE HIGH
 *   >20 auth failures per source IP             -> DBG_ALC_AUTH_FAIL  MEDIUM
 *
 * The auth-failure check is a wire-level heuristic on server responses
 * (PostgreSQL ErrorResponse 'E', MySQL ERR 0xff); userspace refines the
 * verdict with the full protocol parser (internal/proto) before alerting.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#include "dbguard/common.h"
#include "bpf_tracing.h"
#include "dbguard/min_compat.h"

#define DBG_CONN_RATE_MAX       100     /* connects/s before the spike alert */
#define DBG_CONN_FLOOD_MAX      200     /* live conns per client IP          */
#define DBG_AUTH_FAIL_MAX       20      /* auth failures per source IP       */

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

/* Per-second connect buckets. Key: { source IPv4 (network order; 0 for the
 * host-wide bucket used here), second derived from ktime }. Stale entries
 * are swept by the manager; a full bucket only costs the current second. */
struct conn_rate_key {
	__u32 ip;
	__u64 sec;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, struct conn_rate_key);
	__type(value, __u64);
} conn_rate SEC(".maps");

/* Live connections per remote (client) IPv4. Key is the address in
 * NETWORK order, matching every other IPv4 key in DBGuard. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u64);
} active_conns SEC(".maps");

/* Auth-failure responses per source IPv4 (the database side of the wire). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, __u32);
	__type(value, __u64);
} auth_fail SEC(".maps");

/* Per-CPU counters, indexed by the enum below (bpftool map dump friendly). */
enum {
	CONN_SEEN = 0,		/* connects towards DB ports              */
	CONN_ACCEPTED,		/* accepted sockets on DB ports           */
	CONN_CLOSED,		/* closes of DB-port sockets              */
	AUTH_EVENTS,		/* auth-failure responses screened        */
	CONN_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, CONN_MAX);
	__type(key, __u32);
	__type(value, __u64);
} conn_stats SEC(".maps");

static __always_inline void conn_stat_bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&conn_stats, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

/* ---- alert + flow emission ------------------------------------------------ */

#define CONN_ALERT(code, sev, eng, lit)					\
	conn_alert((code), (sev), (eng), (lit), sizeof(lit) - 1)

static __always_inline void conn_alert(__u32 code, __u32 sev, __u32 engine,
				       const char *lit, __u32 lit_len)
{
	struct dbg_alert_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	__builtin_memset(e, 0, sizeof(*e));
	dbg_fill_hdr(&e->hdr, DBG_EVT_ALERT, sev, DBG_ACT_ALERT, engine, 0);
	e->code = code;
	dbg_get_comm(e->comm);
	dbg_bpf_memcpy(e->msg, lit, lit_len);
	bpf_ringbuf_submit(e, 0);
}

/* DBG_EVT_FLOW for the client -> DB direction. IPv4 goes into saddr[0..3]
 * (AF_INET / family 2 implied by the 4-byte copy, remaining bytes zero);
 * sport is the client port, dport the DB port. event: 1 = open, 2 = close. */
static __always_inline void conn_flow_emit(__u32 engine, __u32 raddr,
					   __u16 sport, __u16 dport, __u8 ev)
{
	struct dbg_flow_event *e;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	__builtin_memset(e, 0, sizeof(*e));
	dbg_fill_hdr(&e->hdr, DBG_EVT_FLOW, DBG_SEV_INFO, DBG_ACT_NONE,
		     engine, 0);
	__builtin_memcpy(e->saddr, &raddr, 4);	/* IPv4: 4 bytes, AF_INET */
	e->sport = sport;
	e->dport = dport;
	e->proto = IPPROTO_TCP;
	e->event = ev;
	bpf_ringbuf_submit(e, 0);
}

/* ---- kprobe/tcp_v4_connect ------------------------------------------------- */

/* int tcp_v4_connect(struct sock *sk, struct sockaddr *uaddr, int addrlen)
 * uaddr is the caller-provided sockaddr: a USER pointer. sin_port sits at
 * offset 2 as a big-endian __u16, so a 2-byte user read suffices. */
SEC("kprobe/tcp_v4_connect")
int kp_tcp_v4_connect(struct pt_regs *ctx)
{
	struct dbg_config *cfg;
	struct conn_rate_key rk;
	__be16 sin_port = 0;
	__u64 *cnt;
	__u16 dport;
	__u32 key = 0;
	__u32 engine;

	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg)
		return 0;
	if (bpf_probe_read_user(&sin_port, sizeof(sin_port),
				(const void *)(PT_REGS_PARM2(ctx) + 2)) != 0)
		return 0;
	dport = bpf_ntohs(sin_port);		/* wire -> host order */
	if (dport != cfg->pg_port && dport != cfg->mysql_port)
		return 0;
	conn_stat_bump(CONN_SEEN);
	engine = (dport == cfg->pg_port) ? DBG_ENG_POSTGRES : DBG_ENG_MYSQL;

	/* host-wide per-second bucket (ip = 0) */
	rk.ip = 0;
	rk.sec = bpf_ktime_get_ns() / 1000000000ULL;
	cnt = bpf_map_lookup_elem(&conn_rate, &rk);
	if (!cnt) {
		__u64 one = 1;

		bpf_map_update_elem(&conn_rate, &rk, &one, BPF_NOEXIST);
		cnt = bpf_map_lookup_elem(&conn_rate, &rk);
		if (!cnt)
			return 0;	/* raced away; skip this tick */
	} else {
		__sync_fetch_and_add(cnt, 1);
	}
	if (*cnt > DBG_CONN_RATE_MAX)
		CONN_ALERT(DBG_ALC_CONN_SPIKE, DBG_SEV_MEDIUM, engine,
			   "connect spike: >100/s to DB port");
	return 0;
}

/* ---- kretprobe/inet_csk_accept ---------------------------------------------- */

/* struct sock *inet_csk_accept(struct sock *sk, int flags, int *err,
 *                              bool kern)
 * The DB is the LISTENING side here: skc_num is the LOCAL (DB) port in
 * HOST order, skc_daddr/skc_dport describe the client in NETWORK order. */
SEC("kretprobe/inet_csk_accept")
int krp_inet_csk_accept(struct pt_regs *ctx)
{
	struct dbg_config *cfg;
	struct sock *newsock;
	__u32 raddr;
	__u64 *active;
	__u16 local_port, sport;
	__u32 key = 0;
	__u32 engine;
	long ret = (long)PT_REGS_RC(ctx);

	if (ret <= 0)			/* accept failed: NULL / ERR_PTR */
		return 0;
	newsock = (struct sock *)(unsigned long)ret;
	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg)
		return 0;

	local_port = DBG_CORE_READ(newsock, __sk_common.skc_num);	/* host */
	if (local_port != cfg->pg_port && local_port != cfg->mysql_port)
		return 0;
	engine = (local_port == cfg->pg_port) ? DBG_ENG_POSTGRES : DBG_ENG_MYSQL;

	/* skc_daddr is the REMOTE (client) IPv4, network order */
	raddr = DBG_CORE_READ(newsock, __sk_common.skc_daddr);
	active = bpf_map_lookup_elem(&active_conns, &raddr);
	if (!active) {
		__u64 one = 1;

		bpf_map_update_elem(&active_conns, &raddr, &one, BPF_NOEXIST);
		active = bpf_map_lookup_elem(&active_conns, &raddr);
		if (!active)
			return 0;	/* raced away; skip this tick */
	} else {
		__sync_fetch_and_add(active, 1);
	}
	conn_stat_bump(CONN_ACCEPTED);
	if (*active > DBG_CONN_FLOOD_MAX)
		CONN_ALERT(DBG_ALC_CONN_SPIKE, DBG_SEV_HIGH, engine,
			   "conn flood: >200 live conns per client");

	/* skc_dport is the REMOTE port, network order */
	sport = bpf_ntohs(DBG_CORE_READ(newsock, __sk_common.skc_dport));
	conn_flow_emit(engine, raddr, sport, local_port, 1);
	return 0;
}

/* ---- kprobe/tcp_close -------------------------------------------------------- */

/* void tcp_close(struct sock *sk, long timeout): mirror of the accept hook.
 * The decrement saturates at 0 so a missed accept (map pressure) cannot
 * wrap the counter negative. */
SEC("kprobe/tcp_close")
int kp_tcp_close(struct pt_regs *ctx)
{
	struct dbg_config *cfg;
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	__u32 raddr;
	__u64 *active;
	__u16 local_port, sport;
	__u32 key = 0;
	__u32 engine;

	if (!sk)
		return 0;
	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg)
		return 0;
	local_port = DBG_CORE_READ(sk, __sk_common.skc_num);	/* host order */
	if (local_port != cfg->pg_port && local_port != cfg->mysql_port)
		return 0;
	engine = (local_port == cfg->pg_port) ? DBG_ENG_POSTGRES : DBG_ENG_MYSQL;

	/* skc_daddr: remote IPv4, network order (IPv4 sockets only) */
	raddr = DBG_CORE_READ(sk, __sk_common.skc_daddr);
	active = bpf_map_lookup_elem(&active_conns, &raddr);
	if (active && *active > 0)
		__sync_fetch_and_sub(active, 1);
	conn_stat_bump(CONN_CLOSED);

	/* skc_dport: remote port, network order */
	sport = bpf_ntohs(DBG_CORE_READ(sk, __sk_common.skc_dport));
	conn_flow_emit(engine, raddr, sport, local_port, 2);
	return 0;
}

/* ---- packet parsing -----------------------------------------------------------
 * dbg_flow4 describes a validated Ethernet(+VLAN)/IPv4/TCP packet. Ports are
 * host order (bpf_ntohs applied), src stays network order so it can be used
 * directly as a hash key.
 */
struct dbg_flow4 {
	__u32 src;
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
	/* Byte-wise header length/version instead of the iphdr bitfields:
	 * on little-endian kernels ihl is the low nibble of byte 0. */
	if ((ipb[0] >> 4) != 4)
		return -1;
	ihl = ipb[0] & 0x0f;
	if (ihl < 5)
		return -1;
	if (ip->protocol != IPPROTO_TCP)
		return -1;
	fl->src = ip->saddr;		/* network order */

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

/* ---- cgroup_skb/ingress: auth-failure spike ------------------------------------ */

SEC("cgroup_skb/ingress")
int cgroup_ingress_auth(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct dbg_config *cfg;
	struct dbg_flow4 fl;
	char *p;
	__u32 plen;
	__u64 *fails;
	__u32 key = 0;
	__u32 engine;
	int hit = 0;

	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg)
		return SK_PASS;
	if (dbg_parse_tcp4(data, data_end, &fl))
		return SK_PASS;

	/* Auth failures are SERVER -> client responses, so the DB appears as
	 * the SOURCE port on the ingress path. */
	if (fl.sport != cfg->pg_port && fl.sport != cfg->mysql_port)
		return SK_PASS;

	p = (char *)fl.tcp + (__u32)fl.doff * 4;
	if ((void *)p >= data_end)
		return SK_PASS;
	plen = (__u32)((char *)data_end - p);
	if ((void *)(p + 5) > data_end)	/* verifier: keep p[0..4] in packet bounds */
		plen = 0;
	if (plen < 5)
		return SK_PASS;

	/* Kernel-side heuristic only: userspace refines with the protocol
	 * parser (internal/proto) before surfacing an alert. */
	if (fl.sport == cfg->pg_port) {
		/* PostgreSQL ErrorResponse: 'E' + big-endian length that
		 * counts itself but not the type byte; require a sane length. */
		__u32 mlen = ((__u32)(__u8)p[1] << 24) | ((__u32)(__u8)p[2] << 16) |
			     ((__u32)(__u8)p[3] << 8) | (__u32)(__u8)p[4];

		if (p[0] == 'E' && mlen >= 5 && mlen <= 65535)
			hit = 1;
	} else {
		/* MySQL ERR packet: 3-byte LE payload length, sequence id,
		 * then the 0xff error marker as the first payload byte. */
		if ((__u8)p[4] == 0xff)
			hit = 1;
	}
	if (!hit)
		return SK_PASS;
	conn_stat_bump(AUTH_EVENTS);

	/* fl.src is already in network order, matching the other IPv4 keys */
	fails = bpf_map_lookup_elem(&auth_fail, &fl.src);
	if (!fails) {
		__u64 one = 1;

		bpf_map_update_elem(&auth_fail, &fl.src, &one, BPF_NOEXIST);
		fails = bpf_map_lookup_elem(&auth_fail, &fl.src);
		if (!fails)
			return SK_PASS;	/* raced away; skip this tick */
	} else {
		__sync_fetch_and_add(fails, 1);
	}
	if (*fails > DBG_AUTH_FAIL_MAX) {
		engine = (fl.sport == cfg->pg_port) ? DBG_ENG_POSTGRES :
						       DBG_ENG_MYSQL;
		CONN_ALERT(DBG_ALC_AUTH_FAIL, DBG_SEV_MEDIUM, engine,
			   "auth failures spike");
	}
	return SK_PASS;
}

SEC("license")
char _license[] = DBGUARD_LICENSE;
