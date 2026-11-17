/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * dbguard/common.h - shared wire structs, enums and constants.
 *
 * Every struct here is __attribute__((packed)) and mirrored EXACTLY in
 * internal/ebpf/types.go (Go side decodes ringbuf records binary-wise).
 * Changing a field here REQUIRES updating internal/ebpf/types.go and
 * internal/ebpf/decode.go.
 */
#ifndef __DBGUARD_COMMON_H
#define __DBGUARD_COMMON_H

#include <linux/types.h>
#include "bpf_helpers.h"
#include "bpf_endian.h"
#include "dbguard/helpers.h"

#define DBGUARD_LICENSE "GPL"

/* ---- limits ---- */
#define DBG_MAX_SQL     512
#define DBG_MAX_MSG     256
#define DBG_MAX_PATH    256
#define DBG_MAX_ARGSTR  256
#define DBG_MAX_COMM    16
#define DBG_MAX_ROUTE   128
#define DBG_MAX_SNI     64
#define DBG_PREFIX_LEN  64
#define DBG_MAX_PREFIXES 8

/* ---- event types (hdr.type) ---- */
#define DBG_EVT_QUERY    1   /* SQL query captured at DB dispatch          */
#define DBG_EVT_ALERT    2   /* generic kernel-side alert                  */
#define DBG_EVT_FLOW     3   /* connection open/close/flow summary         */
#define DBG_EVT_EXFIL    4   /* outbound burst / byte-density violation    */
#define DBG_EVT_EXEC     5   /* execve from monitored process              */
#define DBG_EVT_FILE     6   /* sensitive file access attempt              */
#define DBG_EVT_LINEAGE  7   /* app-route <-> query correlation verdict    */
#define DBG_EVT_TENANT   8   /* cross-tenant isolation violation           */
#define DBG_EVT_TLS      9   /* TLS handshake observed on DB port          */
#define DBG_EVT_CONN     10  /* tcp connect/accept tracker event           */

/* ---- engines (hdr.engine) ---- */
#define DBG_ENG_UNKNOWN   0
#define DBG_ENG_POSTGRES  1
#define DBG_ENG_MYSQL     2
#define DBG_ENG_SQLITE    3

/* ---- actions (hdr.action) ---- */
#define DBG_ACT_NONE       0
#define DBG_ACT_ALERT      1
#define DBG_ACT_DROP       2
#define DBG_ACT_RESET      3
#define DBG_ACT_QUARANTINE 4
#define DBG_ACT_KILL       5
#define DBG_ACT_ALLOW      6

/* ---- severities (hdr.severity) ---- */
#define DBG_SEV_INFO     0
#define DBG_SEV_LOW      1
#define DBG_SEV_MEDIUM   2
#define DBG_SEV_HIGH     3
#define DBG_SEV_CRITICAL 4

/* ---- query event flags (query event .flags) - kernel-side pre-scan ---- */
#define DBG_QF_PII_DIGITS   (1ULL << 0) /* long digit runs present        */
#define DBG_QF_LUHN_HIT     (1ULL << 1) /* credit-card-like number (Luhn) */
#define DBG_QF_SSN_LIKE     (1ULL << 2) /* SSN-like 3-2-4 digit pattern   */
#define DBG_QF_SECRET_LIKE  (1ULL << 3) /* high-entropy secret-like token */
#define DBG_QF_DDL          (1ULL << 4) /* DDL statement (DROP/ALTER/TRUNC) */
#define DBG_QF_BULK_SELECT  (1ULL << 5) /* bulk SELECT * hint             */
#define DBG_QF_SQLI_HINT    (1ULL << 6) /* kernel sqli heuristic hit      */

/* ---- alert event codes (alert event .code) ---- */
#define DBG_ALC_SQLI       1
#define DBG_ALC_CONN_SPIKE 2
#define DBG_ALC_AUTH_FAIL  3
#define DBG_ALC_TENANT     4
#define DBG_ALC_PII        5
#define DBG_ALC_EXFIL      6
#define DBG_ALC_RIDS_EXEC  7
#define DBG_ALC_RIDS_FILE  8

/* ---- kernel config block (populated by userspace, map name config_map) ---- */
struct dbg_config {
        __u16 pg_port;        /* PostgreSQL port, host order          */
        __u16 mysql_port;     /* MySQL port, host order               */
        __u8  sqli_enabled;   /* wire-level SQLi firewall on/off      */
        __u8  drop_enabled;   /* allow kernel to DROP (else alert)    */
        __u8  pii_prescan;    /* in-kernel PII pre-scan of queries    */
        __u8  exfil_enabled;  /* exfil breaker accounting on/off      */
        __u8  rids_alert_only;/* RIDS: alert instead of kill/freeze   */
        __u8  lineage_enabled;/* lineage correlation on/off           */
        __u8  pad[2];
};

/* ---- ring buffer event header (16B aligned-friendly) ---- */
struct dbg_hdr {
        __u32 type;
        __u32 action;
        __u32 pid;
        __u32 tid;
        __u32 uid;
        __u32 severity;
        __u32 rule_id;
        __u32 engine;
        __u64 cgroup;
        __u64 ts_ns;
        __u64 session;      /* socket cookie when available, else 0 */
        __u32 data_len;
        __u32 _pad;
} __attribute__((packed));

/* ---- DBG_EVT_QUERY ---- */
struct dbg_query_event {
        struct dbg_hdr hdr;
        char  sql[DBG_MAX_SQL];
        char  comm[DBG_MAX_COMM];
        __u32 sql_len;
        __u32 family;         /* AF_INET / AF_INET6 */
        __u64 flags;          /* DBG_QF_* pre-scan bits */
        __u8  saddr[16];
        __u8  daddr[16];
        __u16 sport;
        __u16 dport;
        __u32 _pad2;
} __attribute__((packed));

/* ---- DBG_EVT_ALERT ---- */
struct dbg_alert_event {
        struct dbg_hdr hdr;
        char msg[DBG_MAX_MSG];
        char comm[DBG_MAX_COMM];
        __u32 code;           /* module-specific code */
        __u32 _pad;
} __attribute__((packed));

/* ---- DBG_EVT_FLOW / DBG_EVT_CONN ---- */
struct dbg_flow_event {
        struct dbg_hdr hdr;
        __u8  saddr[16];
        __u8  daddr[16];
        __u16 sport;
        __u16 dport;
        __u8  proto;          /* IPPROTO_TCP etc. */
        __u8  event;          /* 1=open 2=close 3=summary */
        __u16 _pad2;
        __u64 bytes;
        __u64 packets;
} __attribute__((packed));

/* ---- DBG_EVT_EXFIL ---- */
struct dbg_exfil_event {
        struct dbg_hdr hdr;
        __u64 bytes_window;   /* bytes in offending window  */
        __u64 bytes_total;    /* session cumulative         */
        __u32 window_ms;
        __u32 rate_kbps;
        __u8  verdict;        /* DBG_ACT_* */
        __u8  _pad[3];
        __u8  saddr[16];
        __u8  daddr[16];
        __u16 sport;
        __u16 dport;
        __u16 _pad2;
} __attribute__((packed));

/* ---- DBG_EVT_EXEC ---- */
struct dbg_exec_event {
        struct dbg_hdr hdr;
        char path[DBG_MAX_PATH];
        char argv[DBG_MAX_ARGSTR];
        char comm[DBG_MAX_COMM];
        __s32 argc;
        __u32 verdict;        /* DBG_ACT_* taken (LSM only) */
        __u32 _pad;
} __attribute__((packed));

/* ---- DBG_EVT_FILE ---- */
struct dbg_file_event {
        struct dbg_hdr hdr;
        char path[DBG_MAX_PATH];
        char comm[DBG_MAX_COMM];
        __u32 flags;          /* open flags (O_ACCMODE bits) */
        __u32 verdict;
        __u32 tenant_id;
        __u32 _pad;
} __attribute__((packed));

/* ---- DBG_EVT_LINEAGE ---- */
struct dbg_lineage_event {
        struct dbg_hdr hdr;
        char  route[DBG_MAX_ROUTE];
        __u64 sock_cookie;
        __u32 app_pid;        /* originating application pid, 0 if unknown */
        __u32 flags;          /* 1=hijack-suspected 2=unmatched-route */
        __u32 _pad;
} __attribute__((packed));

/* ---- DBG_EVT_TENANT ---- */
struct dbg_tenant_event {
        struct dbg_hdr hdr;
        char  path[DBG_MAX_PATH];
        __u32 tenant_id;
        __u32 owner_tenant;
        __u32 verdict;
        __u32 _pad;
} __attribute__((packed));

/* ---- DBG_EVT_TLS ---- */
struct dbg_tls_event {
        struct dbg_hdr hdr;
        char  sni[DBG_MAX_SNI];
        __u32 handshake;      /* 1=client_hello seen */
        __u32 version;
        __u32 cipher;
        __u32 _pad;
} __attribute__((packed));

/* Fill the common header. Call from program context. */
static __always_inline void dbg_fill_hdr(struct dbg_hdr *h, __u32 type,
                                         __u32 sev, __u32 action, __u32 engine,
                                         __u64 session)
{
        __u64 pid_tgid = bpf_get_current_pid_tgid();
        __u64 uid_gid  = bpf_get_current_uid_gid();
        h->type     = type;
        h->action   = action;
        h->pid      = pid_tgid >> 32;
        h->tid      = (__u32)pid_tgid;
        h->uid      = (__u32)uid_gid;
        h->severity = sev;
        h->rule_id  = 0;
        h->engine   = engine;
        h->cgroup   = bpf_get_current_cgroup_id();
        h->ts_ns    = bpf_ktime_get_ns();
        h->session  = session;
        h->data_len = 0;
        h->_pad     = 0;
}

/* Copy a bounded, NUL-terminated comm into dst[16]. */
static __always_inline void dbg_get_comm(char *dst)
{
        __builtin_memset(dst, 0, DBG_MAX_COMM);
        bpf_get_current_comm(dst, DBG_MAX_COMM);
}

#endif /* __DBGUARD_COMMON_H */
