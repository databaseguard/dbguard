/* SPDX-License-Identifier: GPL-2.0 */
/* dbguard/src/microseg_sockmap.bpf.c - socket-layer redirection for Cilium sockmap acceleration.
 *
 * Loaded and attached by the Cilium sockmap injection
 * (deploy/cilium/sockmap-enable.yaml): stream_parser / stream_verdict must
 * come as a pair and feed the sockhash, then the sk_msg hook redirects
 * same-endpoint database traffic straight to the peer socket, bypassing
 * the TCP stack for accelerated sidecars.
 *
 * The Go loader deliberately leaves sk_skb_* / sk_msg_* programs
 * unattached (internal/ebpf/loader.go) - the sockmap orchestrator owns
 * their attachment lifecycle.
 *
 * Policy here is narrow by design: only messages whose remote endpoint is
 * a configured database port are redirected into the sockhash; everything
 * else passes untouched (enforcement stays with the XDP / cgroup_skb
 * programs of the other objects).
 */
#include <linux/bpf.h>

#include "dbguard/common.h"

/* helper 58: BPF_FUNC_msg_redirect_hash. The sk_msg context is passed
 * implicitly by the verifier, so only (map, key, flags) are declared. */
static long (*bpf_msg_redirect_hash)(void *msg, void *map, const void *key,
				  unsigned long long flags) = (void *)71;

/* Endpoint key mirrored by the Go side (identity resolver / sockmap
 * orchestrator). */
struct dbg_sockmap_key {
	__u32 ip;		/* remote IPv4, network order */
	__u32 port;		/* remote port, host order    */
};

/* ---- maps --------------------------------------------------------------- */
struct {
	__uint(type, BPF_MAP_TYPE_SOCKHASH);
	__uint(max_entries, 65536);
	__type(key, struct dbg_sockmap_key);
	__type(value, int);	/* socket fd placeholder; the map stores the sock */
} sockhash_endpoints SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct dbg_config);
} config_map SEC(".maps");

/* ---- sk_skb pair ---------------------------------------------------------- */

/* Message boundary parser: every byte is a message boundary for redirect
 * purposes (the sk_msg hook acts per message, not per query). */
SEC("sk_skb/stream_parser")
int stream_parser(struct __sk_buff *skb)
{
	return skb->len;
}

/* Stream verdict: pass everything; DB-port messages are steered in the
 * sk_msg hook below. */
SEC("sk_skb/stream_verdict")
int stream_verdict(struct __sk_buff *skb)
{
	return SK_PASS;
}

/* ---- sk_msg ----------------------------------------------------------------- */

SEC("sk_msg")
int sk_msg_redirect_same(struct sk_msg_md *msg)
{
	struct dbg_config *cfg;
	struct dbg_sockmap_key k;
	__u32 key = 0;
	__u32 remote_port;

	cfg = bpf_map_lookup_elem(&config_map, &key);
	if (!cfg)
		return SK_PASS;

	/* IPv4 endpoints only: family 2 = AF_INET */
	if (msg->family != 2)
		return SK_PASS;

	/* sk_msg_md.remote_port quirk: the port arrives as a BE32 value in
	 * the UPPER 16 bits of the 32-bit field, so read it byte-swapped and
	 * shift down to get the host-order port. */
	remote_port = bpf_ntohl(msg->remote_port) >> 16;
	if (remote_port != cfg->pg_port && remote_port != cfg->mysql_port)
		return SK_PASS;

	k.ip = msg->remote_ip4;		/* network order */
	k.port = remote_port;		/* host order */
	bpf_msg_redirect_hash(msg, &sockhash_endpoints, &k, BPF_F_INGRESS);
	return SK_PASS;
}

SEC("license")
char _license[] = DBGUARD_LICENSE;
