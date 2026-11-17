/* SPDX-License-Identifier: GPL-2.0 */
/* dbguard/src/exfil_breaker.bpf.c - bulk-dump breaker.
 *
 * Accounts bytes per TCP socket around tcp_sendmsg and trips when a 100 ms
 * window carries more than 8 MiB: the signature of a bulk table dump. On a
 * trip the offending client IPv4 is quarantined in exfil_quarantine for
 * 30 s (also enforced packet-wise by cgroup_egress_exfil below and by the
 * Go manager's QuarantineIP API) and a DBG_EVT_EXFIL event is emitted.
 *
 * Address conventions on the sending (workload) socket:
 *   skc_rcv_saddr  LOCAL  IPv4 of the dumper, network order  -> quarantine key
 *   skc_daddr      REMOTE IPv4 of the database, network order
 *   skc_num        local port, host order / skc_dport remote, network order
 *
 * Maps: sessions (sk -> byte accounting, bounded at 16384; the Go side may
 * sweep stale sockets), bridge (kprobe/kretprobe hand-off by pid_tgid),
 * exfil_quarantine (client IPv4 -> expiry in ktime nanoseconds).
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#include "dbguard/common.h"
#include "bpf_tracing.h"
#include "dbguard/min_compat.h"

#define DBG_EXFIL_WIN_NS        100000000ULL	/* 100 ms window        */
#define DBG_EXFIL_WIN_MS        100
#define DBG_EXFIL_LIMIT         (8ULL << 20)	/* 8 MiB per window     */
#define DBG_EXFIL_QUARANTINE_NS 30000000000ULL	/* 30 s quarantine      */

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

/* Per-socket byte accounting. Key: kernel pointer to struct sock. */
struct dbg_session {
	__u64 bytes_total;
	__u64 win_bytes;
	__u64 win_start_ns;
	__u8 quarantined;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u64);		/* (u64) struct sock *            */
	__type(value, struct dbg_session);
} sessions SEC(".maps");

/* kprobe -> kretprobe hand-off: pid_tgid -> struct sock pointer. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u64);		/* bpf_get_current_pid_tgid()     */
	__type(value, __u64);		/* (u64) struct sock *            */
} bridge SEC(".maps");

/* Quarantined source IPv4s. Key is the address in NETWORK order; value is
 * an expiry in ktime ns (kernel side) - the manager seeds the same map from
 * user-space verdicts using unix nanos. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 4096);
	__type(key, __u32);		/* client IPv4, network order     */
	__type(value, __u64);		/* expiry ns                      */
} exfil_quarantine SEC(".maps");

enum {
	EXFIL_FLOWS = 0,	/* sockets with accounted sends        */
	EXFIL_QUARANTINED,	/* windows that tripped the breaker    */
	EXFIL_DROPPED,		/* packets dropped by the cgroup hook  */
	EXFIL_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, EXFIL_MAX);
	__type(key, __u32);
	__type(value, __u64);
} exfil_stats SEC(".maps");

static __always_inline void exfil_stat_bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&exfil_stats, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

/* ---- kprobe/kretprobe on tcp_sendmsg ------------------------------------- */

/* int tcp_sendmsg(struct sock *sk, struct msghdr *msg, size_t size)
 * Stash the socket for the return probe; the update result is discarded on
 * purpose - a lost entry (map pressure) only costs us one accounting tick. */
SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 skp = (__u64)(unsigned long)sk;

	if (!sk)
		return 0;
	bpf_map_update_elem(&bridge, &pid_tgid, &skp, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_sendmsg")
int kretprobe_tcp_sendmsg(struct pt_regs *ctx)
{
	struct dbg_config *cfg;
	struct dbg_session *s;
	struct sock *sk_obj;
	struct dbg_exfil_event *e;
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	__u64 now = bpf_ktime_get_ns();
	__u64 *skp;
	__u64 sk;
	__u32 key = 0;
	__u32 verdict;
	__u32 client_v4;
	__u64 expiry;
	long ret = (long)PT_REGS_RC(ctx);
	__be32 saddr, daddr;
	__u16 sport, dport;

	/* pop the bridge entry no matter what */
	skp = bpf_map_lookup_elem(&bridge, &pid_tgid);
	if (!skp)
		return 0;
	sk = *skp;
	bpf_map_delete_elem(&bridge, &pid_tgid);
	if (ret <= 0 || !sk)
		return 0;
	sk_obj = (struct sock *)(unsigned long)sk;

	/* create the per-socket session on first send */
	s = bpf_map_lookup_elem(&sessions, &sk);
	if (!s) {
		struct dbg_session fresh;

		__builtin_memset(&fresh, 0, sizeof(fresh));
		fresh.win_start_ns = now;
		bpf_map_update_elem(&sessions, &sk, &fresh, BPF_NOEXIST);
		s = bpf_map_lookup_elem(&sessions, &sk);
		if (!s)
			return 0;	/* raced away; skip this tick */
	}
	exfil_stat_bump(EXFIL_FLOWS);

	/* tcp_sendmsg returns the byte count on success or a NEGATIVE errno on
	 * failure (e.g. -EAGAIN). Casting a negative value to __u64 yields a huge
	 * number (~4 GiB) that falsely trips the 8 MiB breaker - which is why a tiny
	 * denied SELECT was being "exfil quarantined". Only account real bytes. */
	if (ret <= 0)
		return 0;

	/* sliding 100 ms window */
	if (s->win_start_ns == 0 ||
	    now - s->win_start_ns >= DBG_EXFIL_WIN_NS) {
		s->win_bytes = 0;
		s->win_start_ns = now;
	}
	s->win_bytes += (__u64)ret;
	s->bytes_total += (__u64)ret;

	cfg = bpf_map_lookup_elem(&config_map, &key);
	verdict = (cfg && cfg->drop_enabled) ? DBG_ACT_RESET : DBG_ACT_QUARANTINE;

	if (!cfg || !cfg->exfil_enabled || s->quarantined ||
	    s->win_bytes <= DBG_EXFIL_LIMIT)
		return 0;

	/* Trip: flag the session, quarantine the local workload address for
	 * 30 s and emit the exfil event for the pipeline. */
	s->quarantined = 1;
	client_v4 = DBG_CORE_READ(sk_obj, __sk_common.skc_rcv_saddr);
	expiry = now + DBG_EXFIL_QUARANTINE_NS;
	bpf_map_update_elem(&exfil_quarantine, &client_v4, &expiry, BPF_ANY);
	exfil_stat_bump(EXFIL_QUARANTINED);

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return 0;
	__builtin_memset(e, 0, sizeof(*e));
	dbg_fill_hdr(&e->hdr, DBG_EVT_EXFIL, DBG_SEV_HIGH, verdict,
		     DBG_ENG_UNKNOWN, 0);
	e->bytes_window = s->win_bytes;
	e->bytes_total = s->bytes_total;
	e->window_ms = DBG_EXFIL_WIN_MS;
	/* bytes over 0.1 s -> kilobits/s: bytes * 8 bits / 0.1 s / 1000 */
	e->rate_kbps = (__u32)((s->win_bytes * 8ULL) / 100ULL);
	e->verdict = (__u8)verdict;
	saddr = DBG_CORE_READ(sk_obj, __sk_common.skc_rcv_saddr); /* network */
	daddr = DBG_CORE_READ(sk_obj, __sk_common.skc_daddr);     /* network */
	__builtin_memcpy(e->saddr, &saddr, 4);	/* IPv4: 4 bytes, AF_INET */
	__builtin_memcpy(e->daddr, &daddr, 4);
	sport = DBG_CORE_READ(sk_obj, __sk_common.skc_num);	/* host */
	dport = bpf_ntohs(DBG_CORE_READ(sk_obj, __sk_common.skc_dport));
	e->sport = sport;
	e->dport = dport;
	bpf_ringbuf_submit(e, 0);
	return 0;
}

/* ---- cgroup_skb/egress: enforce quarantine -------------------------------- */

struct dbg_flow4 {
	__u32 src;		/* IPv4 source address, network order */
	__u16 dport;		/* TCP destination port, host order   */
};

/* Minimal Ethernet/IPv4/TCP parse (no VLAN: cgroup egress on container
 * hosts never sees tags). All accesses bounds-checked against data_end. */
static __always_inline int dbg_parse_flow_v4(void *data, void *data_end,
					     struct dbg_flow4 *fl)
{
	struct ethhdr *eth = data;
	struct iphdr *ip;
	__u8 *ipb;
	struct tcphdr *tcp;
	__u32 ihl;

	if ((void *)(eth + 1) > data_end)
		return -1;
	if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
		return -1;
	ip = (void *)eth + sizeof(*eth);
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
	fl->src = ip->saddr;

	tcp = (void *)ip + (__u64)ihl * 4;
	if ((void *)(tcp + 1) > data_end)
		return -1;
	fl->dport = bpf_ntohs(tcp->dest);
	return 0;
}

SEC("cgroup_skb/egress")
int cgroup_egress_exfil(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct dbg_config *cfg;
	struct dbg_flow4 fl;
	__u64 *expiry;
	__u64 now;
	__u32 key = 0;

	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg)
		return SK_PASS;
	if (dbg_parse_flow_v4(data, data_end, &fl))
		return SK_PASS;

	/* only traffic towards a database wire port is screened; the
	 * quarantine is keyed by the SOURCE workload address, so the hook
	 * enforces on hosts whose egress path carries the dumper's packets. */
	if (fl.dport != cfg->pg_port && fl.dport != cfg->mysql_port)
		return SK_PASS;

	now = bpf_ktime_get_ns();
	expiry = bpf_map_lookup_elem(&exfil_quarantine, &fl.src);
	if (expiry && *expiry > now) {
		exfil_stat_bump(EXFIL_DROPPED);
		return SK_DROP;
	}
	return SK_PASS;
}

SEC("license")
char _license[] = DBGUARD_LICENSE;
