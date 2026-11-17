/* SPDX-License-Identifier: GPL-2.0 */
/* dbguard/src/sqli_firewall.bpf.c - kernel SQLi firewall for the
 * PostgreSQL and MySQL wire protocols.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>

#include "dbguard/common.h"
#include "dbguard/min_compat.h"

#define DBG_SQLI_SNIP 256       /* stack snippet scanned per packet */

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

/* Trusted client CIDRs (LPM). Key matches the Go loader's lpmKey:
 * { u32 prefixlen; u32 addr (big endian / network order) }. */
struct lpm4_key {
        __u32 prefixlen;
        __u32 addr;
};

struct {
        __uint(type, BPF_MAP_TYPE_LPM_TRIE);
        __uint(max_entries, 4096);
        __type(key, struct lpm4_key);
        __type(value, __u8);            /* 1 = trusted, skip detection */
        __uint(map_flags, BPF_F_NO_PREALLOC);
} client_allow SEC(".maps");

/* Per-CPU counters, indexed by the enum below (bpftool map dump friendly). */
enum {
        SQLI_SCANNED = 0,       /* packets whose SQL reached the scorer */
        SQLI_DETECTED,          /* signature hits                       */
        SQLI_DROPPED,           /* packets actually dropped             */
        SQLI_MAX,
};

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, SQLI_MAX);
        __type(key, __u32);
        __type(value, __u64);
} sqli_stats SEC(".maps");


struct sqli_win_rec {
        __u32 rule_id;
        __u32 sql_len;
        __u64 ts_ns;
        char  sql[496];
};                                      /* sizeof == 512 */

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, struct sqli_win_rec);
} sqli_win SEC(".maps");

/* ---- rule ids (surfaced as hdr.rule_id on alerts) ------------------------ */
#define SQLI_R_OR_TAUT       1  /* OR 1=1                    */
#define SQLI_R_STR_TAUT      2  /* '1'='1                    */
#define SQLI_R_STR_TAUT2     3  /* 1'='1                     */
#define SQLI_R_UNION         4  /* UNION SELECT              */
#define SQLI_R_STACKED       5  /* "; --" stacked queries    */
#define SQLI_R_COMMENT_DASH  6  /* '-- comment trick         */
#define SQLI_R_COMMENT_BLOCK 7  /* /* obfuscation            */
#define SQLI_R_SLEEP         8  /* SLEEP(                    */
#define SQLI_R_BENCHMARK     9  /* BENCHMARK(                */
#define SQLI_R_PG_SLEEP      10 /* pg_sleep(                 */
#define SQLI_R_WAITFOR       11 /* WAITFOR DELAY             */
#define SQLI_R_XPCMDSHELL    12 /* xp_cmdshell               */
#define SQLI_R_INFOSCHEMA    13 /* information_schema        */
#define SQLI_R_LOAD_FILE     14 /* load_file(                */
#define SQLI_R_OUTFILE       15 /* INTO OUTFILE              */
#define SQLI_R_NUL_BYTE      16 /* %00 smuggled NUL          */

/* ---- packet parsing -------------------------------------------------------
 * dbg_flow4 describes a validated IPv4/TCP packet. Ports are host order
 * (bpf_ntohs applied), src stays network order so it can be used directly
 * as an LPM / hash key.
 */
struct dbg_flow4 {
        __u32 src;
        __u16 sport;
        __u16 dport;
        __u8 doff;              /* TCP data offset, 32-bit words */
        __u8 ihl;               /* v27: IPv4 IHL, 32-bit words   */
        __u16 l2_off;           /* v27: L2 framing bytes         */
        struct tcphdr *tcp;
};

/* Common tail: validate the TCP header at a known pointer and fill the
 * ports/doff fields. Caller has already bounded tcp[0..19] against data_end
 * and stored src. */
static __always_inline int dbg_tcp_tail(struct tcphdr *tcp, void *data_end,
                                        struct dbg_flow4 *fl)
{
        fl->tcp = tcp;
        fl->sport = bpf_ntohs(tcp->source);     /* wire -> host order */
        fl->dport = bpf_ntohs(tcp->dest);
        fl->doff = (((const __u8 *)tcp)[12] >> 4) & 0xf;
        if (fl->doff < 5)
                return -1;
        return 0;
}

/* L2 parser: Ethernet (+ one optional 802.1Q tag) / IPv4 / TCP. Used by the
 * XDP hook, which always sees frames, and by the cgroup hook only as a
 * fallback when the buffer does not start with an IPv4 header. */
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
        fl->src = ip->saddr;            /* network order */

        tcp = (void *)ip + (__u64)ihl * 4;
        if ((void *)(tcp + 1) > data_end)       /* covers the fixed 20B header */
                return -1;
        if (dbg_tcp_tail(tcp, data_end, fl))
                return -1;
        fl->ihl = (__u8)ihl;
        fl->l2_off = (__u16)hlen;
        return 0;
}

static __always_inline int dbg_parse_tcp4_l3(void *data, void *data_end,
                                             struct dbg_flow4 *fl)
{
        struct iphdr *ip = data;
        __u8 *ipb = (__u8 *)data;
        struct tcphdr *tcp;
        __u16 frag;
        __u32 ihl;

        if ((void *)(ip + 1) > data_end)
                return -1;
        if ((ipb[0] >> 4) != 4)
                return 1;               /* not IPv4 at this offset */
        ihl = ipb[0] & 0x0f;
        if (ihl < 5)
                return -1;
        if (ip->protocol != IPPROTO_TCP)
                return -1;
        /* non-first fragments carry no TCP header */
        frag = (__u16)(((__u16)ipb[6] << 8) | (__u16)ipb[7]);
        if (frag & 0x1fff)
                return -1;
        fl->src = ip->saddr;            /* network order */

        tcp = (void *)ip + (__u64)ihl * 4;
        if ((void *)(tcp + 1) > data_end)
                return -1;
        if (dbg_tcp_tail(tcp, data_end, fl))
                return -1;
        fl->ihl = (__u8)ihl;
        fl->l2_off = 0;
        return 0;
}

/* ---- protocol sniffing --------------------------------------------------- */

/* PostgreSQL 'Q' (simple query): 1 type byte, then a big-endian length that
 * counts itself but not the type byte, then the SQL text. */
static __always_inline int dbg_pg_query(const __u8 *p, __u32 plen,
                                        __u32 *sql_off, __u32 *sql_avail)
{
        __u32 mlen;

        if (plen < 5)
                return 0;
        if (p[0] != 'Q')
                return 0;
        mlen = ((__u32)p[1] << 24) | ((__u32)p[2] << 16) |
               ((__u32)p[3] << 8) | (__u32)p[4];
        if (mlen < 5 || mlen > 65535)
                return 0;
        *sql_off = 5;
        *sql_avail = mlen - 4;
        return 1;
}

/* MySQL COM_QUERY: 3-byte little-endian payload length, sequence id, then
 * the command byte (0x03 = COM_QUERY), then the SQL text. */
static __always_inline int dbg_mysql_query(const __u8 *p, __u32 plen,
                                           __u32 *sql_off, __u32 *sql_avail)
{
        __u32 mlen;

        if (plen < 5)
                return 0;
        mlen = (__u32)p[0] | ((__u32)p[1] << 8) | ((__u32)p[2] << 16);
        if (p[4] != 0x03)
                return 0;
        if (mlen < 1 || mlen > 16384)
                return 0;
        *sql_off = 5;
        *sql_avail = mlen - 1;
        return 1;
}

static __always_inline int dbg_sql_gate(struct dbg_flow4 *fl, __u32 engine,
                                        void *data_end, __u32 *avail_out)
{
        char *p = (char *)fl->tcp + (__u32)fl->doff * 4;
        __u32 plen;
        __u32 off = 0;
        __u32 avail = 0;

        if ((void *)p >= data_end)
                return 0;
        plen = (__u32)((char *)data_end - p);
        if ((void *)(p + 5) > data_end) /* verifier: keep p[0..4] in packet bounds */
                plen = 0;
        if (engine == DBG_ENG_POSTGRES) {
                if (!dbg_pg_query((__u8 *)p, plen, &off, &avail))
                        return 0;
        } else if (engine == DBG_ENG_MYSQL) {
                if (!dbg_mysql_query((__u8 *)p, plen, &off, &avail))
                        return 0;
        } else {
                return 0;
        }
        if (avail == 0)
                return 0;
        *avail_out = avail;
        return 1;
}


#define dbg_barrier_var(var) __asm__ __volatile__("" : "+r"(var))

static __always_inline __u32 dbg_sniff_sql_skb(struct __sk_buff *skb,
                                               __u32 pay_base, __u32 pay_avail,
                                               __u32 engine, char *out)
{
        __u8 hdr[5];
        __u32 off;
        __u32 avail;
        __u32 want;
        __u32 w2;
        __u32 c;
        __u32 room;
        __u32 i;
        __u32 idx;

        if (pay_avail < 5)
                return 0;
        if (bpf_skb_load_bytes(skb, pay_base, hdr, sizeof(hdr)))
                return 0;

        if (engine == DBG_ENG_POSTGRES) {
                if (!dbg_pg_query(hdr, pay_avail, &off, &avail))
                        return 0;
        } else if (engine == DBG_ENG_MYSQL) {
                if (!dbg_mysql_query(hdr, pay_avail, &off, &avail))
                        return 0;
        } else {
                return 0;
        }

        if (avail > DBG_SQLI_SNIP - 1)
                avail = DBG_SQLI_SNIP - 1;
        if (avail == 0)
                return 0;
        want = avail;

        /* zero-fill first: bytes never written below stay defined */
        __builtin_memset(out, 0, DBG_SQLI_SNIP);

#pragma unroll
        for (i = 0; i < 4; i++) {
                __u32 o = i * 64;

                room = pay_avail - 5 - o;
                if ((__s32)room < 1)
                        room = 1;
                else if (room > 64)
                        room = 64;

 
                w2 = want;
                dbg_barrier_var(w2);
                if (w2 <= o) {
                        c = 64;
                } else {
                        c = w2 - o;
                        dbg_barrier_var(c);
                        if ((__s32)c < 1)
                                c = 1;
                        else if (c > 64)
                                c = 64;
                        if (c > room)
                                c = room;
                }
                dbg_barrier_var(c);
                if (c < 1)
                        c = 1;
                else if (c > 64)
                        c = 64;

                bpf_skb_load_bytes(skb, pay_base + off + o, out + o, c);
        }

        w2 = 0;
        dbg_barrier_var(w2);
        c = 0;
        dbg_barrier_var(c);
        room = 0;
        dbg_barrier_var(room);

        idx = want;
        dbg_barrier_var(idx);
        if (idx > DBG_SQLI_SNIP - 1)
                idx = DBG_SQLI_SNIP - 1;
        out[idx] = 0;
        return want;
}


static inline __attribute__((always_inline)) int
dbg_ci_flat(const char *hay, const char *hay_end, unsigned int hay_max,
            const char *needle, unsigned int needle_len)
{
        unsigned int notfound = 1;
        unsigned int run = 1;
        const __u8 *pos;
        unsigned int i, j;

#pragma clang loop unroll(disable)
        for (i = 0; i + needle_len <= hay_max; i++) {
                pos = (const __u8 *)hay + i;
                /* packet-edge bound: for stack scans (hay_end = hay +
                 * hay_max) the loop guard already caps i + needle_len at
                 * hay_max, so this folds to a compile-time false. */
                if (pos + needle_len > (const __u8 *)hay_end)
                        break;
                {
                        __u32 c0 = (__u32)pos[0];
                        __u32 diff = 0;

                        run &= ((c0 | (0u - c0)) >> 8) & 1u;   /* 0 once a NUL is seen */
#pragma unroll
                        for (j = 0; j < needle_len; j++)
                                diff |= ((__u32)pos[j] ^
                                         (__u32)(__u8)needle[j]) & 0xDFu;
                        dbg_barrier_var(diff);  /* opaque to the optimizer: the zero-test must
                                                 * stay off the lanes */
                        {
                                __u32 nz = diff | (0u - diff);

                                dbg_barrier_var(nz);    
                                notfound &= ((nz >> 31) | (run ^ 1u));
                        }
                }
        }

        pos = (const __u8 *)hay;
        dbg_barrier_var(pos);
        i = 0;
        dbg_barrier_var(i);
        return (int)(notfound ^ 1u);
}

static __always_inline int dbg_sqli_score(const char *hay, const char *hay_end,
                                          __u32 *rule_id)
{
        __u32 mask = 0;
        __u32 n;

#define SQLI_PROBE(pat, id)\
        mask |= (__u32)dbg_ci_flat(hay, hay_end, DBG_HAY_MAX, pat, sizeof(pat) - 1) \
                << ((id) - 1)

        SQLI_PROBE("or 1=1", SQLI_R_OR_TAUT);
        SQLI_PROBE("'1'='1", SQLI_R_STR_TAUT);
        SQLI_PROBE("1'='1", SQLI_R_STR_TAUT2);
        SQLI_PROBE("union select", SQLI_R_UNION);
        SQLI_PROBE("; --", SQLI_R_STACKED);
        SQLI_PROBE("'--", SQLI_R_COMMENT_DASH);
        SQLI_PROBE("/*", SQLI_R_COMMENT_BLOCK);
        SQLI_PROBE("sleep(", SQLI_R_SLEEP);
        SQLI_PROBE("benchmark(", SQLI_R_BENCHMARK);
        SQLI_PROBE("pg_sleep(", SQLI_R_PG_SLEEP);
        SQLI_PROBE("waitfor delay", SQLI_R_WAITFOR);
        SQLI_PROBE("xp_cmdshell", SQLI_R_XPCMDSHELL);
        SQLI_PROBE("information_schema", SQLI_R_INFOSCHEMA);
        SQLI_PROBE("load_file(", SQLI_R_LOAD_FILE);
        SQLI_PROBE("into outfile", SQLI_R_OUTFILE);
        SQLI_PROBE("%00", SQLI_R_NUL_BYTE);

#undef SQLI_PROBE

        if (!mask)
                return 0;
        for (n = 0; n < 16; n++) {            /* lowest set bit = first hit */
                if (mask & (1u << n))
                        break;
        }
        *rule_id = n + 1;
        return 1;
}

/* ---- stats + capture + alert emission ------------------------------------ */

static __always_inline void sqli_stat_bump(__u32 idx)
{
        __u64 *v = bpf_map_lookup_elem(&sqli_stats, &idx);

        if (v)
                __sync_fetch_and_add(v, 1);
}


static __always_inline void sqli_capture(__u32 rule_id, const char *sql,
                                         __u32 sql_len)
{
        struct sqli_win_rec *w;
        __u32 k = 0;
        __u32 i;

        w = bpf_map_lookup_elem(&sqli_win, &k);
        if (!w)
                return;
        /* volatile destination: keep LLVM from re-forming a memcpy libcall
         * (unsupported on the BPF target, same trick as dbg_bpf_memcpy). */
        for (i = 0; i < DBG_SQLI_SNIP; i++) {           /* constant bound */
                ((volatile char *)w->sql)[i] = sql[i];
        }
        w->rule_id = rule_id;
        w->sql_len = sql_len;
        w->ts_ns = bpf_ktime_get_ns();
}


static __always_inline void sqli_alert(__u32 rule_id, __u32 engine,
                                       __u32 action, const char *sql,
                                       __u32 sql_len)
{
        struct dbg_alert_event *e;
        __u32 i;

        e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
        if (!e)
                return;
        __builtin_memset(e, 0, sizeof(*e));
        dbg_fill_hdr(&e->hdr, DBG_EVT_ALERT, DBG_SEV_HIGH, action, engine, 0);
        e->hdr.rule_id = rule_id;
        e->code = DBG_ALC_SQLI;

        __builtin_memcpy(e->msg, "sqli hit: ", 10);
#pragma clang loop unroll(disable)
        for (i = 0; i < DBG_MAX_MSG - 11; i++) {        /* constant bound */
                char c;

                if (i >= sql_len)
                        break;
                c = sql[i];
                if (c == '\0')
                        break;
                e->msg[10 + i] = c;
        }
        bpf_ringbuf_submit(e, 0);
}

/* ---- cgroup_skb/egress ----------------------------------------------------
 * The kernel delivers L3 skbs here (data starts at the IPv4 header). Parse
 * L3 first; if the buffer does not start with an IPv4 header, fall back to
 * the L2 frame parser so the same object also tolerates L2-shaped delivery.
 * The payload is sniffed through bpf_skb_load_bytes(), so paged fragments
 * are covered end to end.
*/

SEC("cgroup_skb/egress")
int cgroup_egress_sqli(struct __sk_buff *skb)
{
        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;
        struct dbg_config *cfg;
        struct dbg_flow4 fl;
        struct lpm4_key k;
        char sql[DBG_SQLI_SNIP];
        __u8 *trusted;
        __u32 key = 0;
        __u32 rule_id = 0;
        __u32 engine;
        __u32 sql_len;
        __u32 pay_base;
        __u32 pay_avail;
        int rc;

        cfg = bpf_map_lookup_elem(&config_map, &key);
        if (!cfg)
                return SK_PASS;
        if (!cfg->sqli_enabled)
                return SK_PASS;

        /* cgroup egress sees L3: parse L3 first, L2 as the fallback */
        rc = dbg_parse_tcp4_l3(data, data_end, &fl);
        if (rc == 1)
                rc = dbg_parse_tcp4(data, data_end, &fl);
        if (rc)
                return SK_PASS;

        /* only the DB wire ports (config ports are host order) */
        if (fl.dport != cfg->pg_port && fl.dport != cfg->mysql_port)
                return SK_PASS;

        /* trusted CIDRs bypass the wire firewall */
        k.prefixlen = 32;
        k.addr = fl.src;                /* network order, matches userspace */
        trusted = bpf_map_lookup_elem(&client_allow, &k);
        if (trusted)
                return SK_PASS;

        engine = (fl.dport == cfg->pg_port) ? DBG_ENG_POSTGRES : DBG_ENG_MYSQL;

        /* payload offset/length relative to skb->data, paged frags included */
        pay_base = (__u32)fl.l2_off + (__u32)fl.ihl * 4 + (__u32)fl.doff * 4;
        if ((__u32)skb->len < pay_base + 5)
                return SK_PASS;
        pay_avail = (__u32)skb->len - pay_base;

        sql_len = dbg_sniff_sql_skb(skb, pay_base, pay_avail, engine, sql);
        if (!sql_len)
                return SK_PASS;
        sqli_stat_bump(SQLI_SCANNED);

        if (!dbg_sqli_score(sql, sql + DBG_HAY_MAX, &rule_id))
                return SK_PASS;
        sqli_stat_bump(SQLI_DETECTED);
        sqli_capture(rule_id, sql, sql_len);

        if (cfg->drop_enabled) {
                sqli_stat_bump(SQLI_DROPPED);
                sqli_alert(rule_id, engine, DBG_ACT_DROP, sql, sql_len);
                return SK_DROP;
        }
        sqli_alert(rule_id, engine, DBG_ACT_ALERT, sql, sql_len);
        return SK_PASS;
}


SEC("xdp")
int xdp_sqi_guard(struct xdp_md *ctx)
{
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;
        struct dbg_config *cfg;
        struct dbg_flow4 fl;
        const char *hay;
        char sql[DBG_SQLI_SNIP];
        __u32 key = 0;
        __u32 rule_id = 0;
        __u32 engine;
        __u32 sql_len;
        __u32 avail = 0;
        __u32 i;

        cfg = bpf_map_lookup_elem(&config_map, &key);
        if (!cfg)
                return XDP_PASS;
        if (!cfg->sqli_enabled)
                return XDP_PASS;
        if (dbg_parse_tcp4(data, data_end, &fl))
                return XDP_PASS;
        if (fl.dport != cfg->pg_port && fl.dport != cfg->mysql_port)
                return XDP_PASS;

        engine = (fl.dport == cfg->pg_port) ? DBG_ENG_POSTGRES : DBG_ENG_MYSQL;

        if (!dbg_sql_gate(&fl, engine, data_end, &avail))
                return XDP_PASS;

        hay = (const char *)fl.tcp + (__u32)fl.doff * 4 + 5;
        if (hay + DBG_HAY_MAX > (const char *)data_end)
                return XDP_PASS;        /* window does not fit: cgroup covers it */

        __builtin_memset(sql, 0, DBG_SQLI_SNIP);
#pragma unroll
        for (i = 0; i < DBG_HAY_MAX; i++)
                sql[i] = hay[i];        /* all 96 loads proven by the ONE check above */
        sqli_stat_bump(SQLI_SCANNED);

        if (!dbg_sqli_score(sql, sql + DBG_HAY_MAX, &rule_id))
                return XDP_PASS;
        sqli_stat_bump(SQLI_DETECTED);

        /* post-scan length clamp: taken side is the CONSTANT DBG_HAY_MAX,
         * which prunes against the [1,DBG_HAY_MAX] fall-through; the scan
         * is already behind us either way */
        sql_len = avail;
        if (sql_len > DBG_HAY_MAX)
                sql_len = DBG_HAY_MAX;
        sql[sql_len] = 0;               /* NUL sentinel at the text end */
        sqli_capture(rule_id, sql, sql_len);

        if (cfg->drop_enabled) {
                sqli_stat_bump(SQLI_DROPPED);
                sqli_alert(rule_id, engine, DBG_ACT_DROP, sql, sql_len);
                return XDP_DROP;
        }
        sqli_alert(rule_id, engine, DBG_ACT_ALERT, sql, sql_len);
        return XDP_PASS;
}

SEC("license")
char _license[] = DBGUARD_LICENSE;
