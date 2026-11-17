/* SPDX-License-Identifier: GPL-2.0 */
/* dbguard/src/microseg_xdp.bpf.c - (XDP path): identity-aware micro-segmentation.
 *
 * Attached to the workload-facing interface (native driver mode where the
 * NIC supports it, generic fallback otherwise), this program enforces
 * per-client LPM policy for traffic towards the database ports BEFORE the
 * socket layer sees the packet:
 *
 *   client_policy  LPM trie keyed by client CIDR; value bits:
 *                  bit0 = allow, bit1 = deny, bit2 = quarantine
 *   ip_identity    Cilium identity per client IPv4 (alert enrichment)
 *
 * Verdict order for a DB-port packet:
 *   deny / quarantine bit   -> XDP_DROP + DBG_ALC_CONN_SPIKE alert
 *   allow bit               -> XDP_PASS
 *   no (matching) entry     -> XDP_DROP when config.drop_enabled, else pass
 *                              (default-deny micro-segmentation mode)
 *
 * IPv6 is counted and passed: v6 policy is planned (NOTE below); the IPv4
 * path here is the real implementation.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#include "dbguard/common.h"
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

/* LPM key matches the Go loader's lpmKey:
 * { u32 prefixlen; u32 addr (big endian / network order) }. */
struct lpm4_key {
	__u32 prefixlen;
	__u32 addr;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 4096);
	__type(key, struct lpm4_key);
	__type(value, __u8);	/* bit0 allow bit1 deny bit2 quarantine */
	__uint(map_flags, BPF_F_NO_PREALLOC);
} client_policy SEC(".maps");

/* Cilium identity per client IPv4 (network-order key), populated by the
 * manager from the Cilium identity resolver; used only for enrichment. */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 16384);
	__type(key, __u32);
	__type(value, __u32);
} ip_identity SEC(".maps");

/* Per-CPU counters, indexed by the enum below (bpftool map dump friendly). */
enum {
	XDP_STAT_PASS = 0,	/* packets this hook let through         */
	XDP_STAT_DROP,		/* packets this hook dropped             */
	XDP_STAT_V6,		/* IPv6 packets scanned (v6 policy: planned) */
	XDP_STAT_MAX,
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, XDP_STAT_MAX);
	__type(key, __u32);
	__type(value, __u64);
} xdp_stats SEC(".maps");

static __always_inline void xdp_stat_bump(__u32 idx)
{
	__u64 *v = bpf_map_lookup_elem(&xdp_stats, &idx);

	if (v)
		__sync_fetch_and_add(v, 1);
}

/* ---- alert emission ---------------------------------------------------------- */

/* DBG_ALC_CONN_SPIKE alert for a micro-seg deny; appends the Cilium
 * identity as " identity=<decimal>" when the client is known. */
static __always_inline void microseg_alert(__u32 ident, int have_ident)
{
	struct dbg_alert_event *e;
	char digits[10];	/* __u32 is at most 10 decimal digits */
	__u32 pos = 16;		/* strlen("micro-seg denied") */
	__u32 n = 0;
	__u32 v = ident;
	__u32 i;

	e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e)
		return;
	__builtin_memset(e, 0, sizeof(*e));
	dbg_fill_hdr(&e->hdr, DBG_EVT_ALERT, DBG_SEV_HIGH, DBG_ACT_DROP,
		     DBG_ENG_UNKNOWN, 0);
	e->code = DBG_ALC_CONN_SPIKE;
	__builtin_memcpy(e->msg, "micro-seg denied", 16);
	if (have_ident) {
		__builtin_memcpy(e->msg + pos, " identity=", 10);
		pos += 10;
		/* decimal render, least-significant digit first */
		for (i = 0; i < 10; i++) {	/* constant bound */
			if (v == 0 && n > 0)
				break;
			digits[n++] = '0' + (v % 10);
			v /= 10;
		}
		for (i = 0; i < 10; i++) {	/* constant bound */
			if (i >= n || pos >= DBG_MAX_MSG - 1)
				break;
			{
				__u32 dbg_di = (__u32)(n - 1 - i);

				if (dbg_di < sizeof(digits))
					e->msg[pos] = digits[dbg_di];
			}
			pos++;
		}
	}
	bpf_ringbuf_submit(e, 0);
}

/* ---- XDP ingress ---------------------------------------------------------------- */

SEC("xdp")
int xdp_microseg(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct dbg_config *cfg;
	struct ethhdr *eth = data;
	struct dbg_vlan_hdr *vlan;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct lpm4_key lk;
	__u8 *ipb;
	__u8 *pol;
	__u32 ident = 0;
	__u32 key = 0;
	__u64 hlen = sizeof(*eth);
	__u32 src;
	__u32 ihl;
	__u16 proto, dport;
	int have_ident = 0;

	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg)
		return XDP_PASS;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	proto = bpf_ntohs(eth->h_proto);

	/* One optional 802.1Q tag (same handling as sqli_firewall). */
	if (proto == ETH_P_8021Q) {
		vlan = (void *)eth + hlen;
		if ((void *)(vlan + 1) > data_end)
			return XDP_PASS;
		proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
		hlen += sizeof(*vlan);
	}

	if (proto == ETH_P_IPV6) {
		/* NOTE: v6 policy planned: counted and passed for now; the
		 * IPv4 path below is the real implementation. */
		xdp_stat_bump(XDP_STAT_V6);
		return XDP_PASS;
	}
	if (proto != ETH_P_IP) {
		xdp_stat_bump(XDP_STAT_PASS);
		return XDP_PASS;
	}

	ip = (void *)eth + hlen;
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	ipb = (__u8 *)ip;
	/* Byte-wise header length/version instead of the iphdr bitfields:
	 * on little-endian kernels ihl is the low nibble of byte 0. */
	if ((ipb[0] >> 4) != 4) {
		xdp_stat_bump(XDP_STAT_PASS);
		return XDP_PASS;
	}
	ihl = ipb[0] & 0x0f;
	if (ihl < 5) {
		xdp_stat_bump(XDP_STAT_PASS);
		return XDP_PASS;
	}
	if (ip->protocol != IPPROTO_TCP) {
		xdp_stat_bump(XDP_STAT_PASS);
		return XDP_PASS;
	}
	src = ip->saddr;		/* network order */

	tcp = (void *)ip + (__u64)ihl * 4;
	if ((void *)(tcp + 1) > data_end) {	/* covers the fixed 20B header */
		xdp_stat_bump(XDP_STAT_PASS);
		return XDP_PASS;
	}
	dport = bpf_ntohs(tcp->dest);	/* wire -> host order */

	/* micro-seg policy applies to the DB wire ports only */
	if (dport != cfg->pg_port && dport != cfg->mysql_port) {
		xdp_stat_bump(XDP_STAT_PASS);
		return XDP_PASS;
	}

	lk.prefixlen = 32;
	lk.addr = src;			/* network order, matches userspace */
	pol = bpf_map_lookup_elem(&client_policy, &lk);
	if (pol) {
		if ((*pol & 0x2) || (*pol & 0x4)) {	/* deny / quarantine */
			__u32 *idp = bpf_map_lookup_elem(&ip_identity, &src);

			if (idp) {
				ident = *idp;
				have_ident = 1;
			}
			xdp_stat_bump(XDP_STAT_DROP);
			microseg_alert(ident, have_ident);
			return XDP_DROP;
		}
		if (*pol & 0x1) {	/* explicit allow */
			xdp_stat_bump(XDP_STAT_PASS);
			return XDP_PASS;
		}
	}

	/* no (or bit-less) policy entry: default-deny when the agent is
	 * allowed to drop, else observe-only */
	if (cfg->drop_enabled) {
		xdp_stat_bump(XDP_STAT_DROP);
		return XDP_DROP;
	}
	xdp_stat_bump(XDP_STAT_PASS);
	return XDP_PASS;
}

SEC("license")
char _license[] = DBGUARD_LICENSE;
