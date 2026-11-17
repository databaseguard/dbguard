/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * dbguard/helpers.h - BPF helper function declarations used by DBGuard.
 * Self-contained build: no libbpf-dev required at compile time.
 */
#ifndef __DBGUARD_HELPERS_H
#define __DBGUARD_HELPERS_H


#define DBG_FORCE_INLINE inline __attribute__((always_inline))

/* BPF target has no libc memset/memcpy; use byte loops.
 * volatile stores keep LLVM from re-forming mem* libcalls. */
static inline void dbg_bpf_memset(void *dst, unsigned char v, unsigned int n) {
    for (unsigned int i = 0; i < n; i++)
        ((volatile unsigned char *)dst)[i] = v;
}
static inline void dbg_bpf_memcpy(void *dst, const void *src, unsigned int n) {
    for (unsigned int i = 0; i < n; i++)
        ((volatile unsigned char *)dst)[i] = ((const volatile unsigned char *)src)[i];
}

/* map helpers */
static void *(*bpf_map_lookup_elem)(const void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(const void *map, const void *key, const void *value, unsigned long long flags) = (void *)2;
static long (*bpf_map_delete_elem)(const void *map, const void *key) = (void *)3;

/* process / cgroup context */
static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void *)14;
static unsigned long long (*bpf_get_current_uid_gid)(void) = (void *)15;
static long (*bpf_get_current_comm)(void *buf, unsigned int size) = (void *)16;
static unsigned long long (*bpf_get_current_cgroup_id)(void) = (void *)80;
static unsigned long long (*bpf_get_current_task)(void) = (void *)35;

/* time & randomness */
static unsigned long long (*bpf_ktime_get_ns)(void) = (void *)5;

/* ring buffer (Linux >= 5.8) */
static void *(*bpf_ringbuf_reserve)(void *ringbuf, unsigned long long size, unsigned long long flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, unsigned long long flags) = (void *)132;
static void (*bpf_ringbuf_discard)(void *data, unsigned long long flags) = (void *)133;
static long (*bpf_ringbuf_output)(void *ringbuf, void *data, unsigned long long size, unsigned long long flags) = (void *)130;

/* data reads */
static long (*bpf_probe_read_kernel)(void *dst, unsigned int size, const void *unsafe_ptr) = (void *)113;
static long (*bpf_probe_read_user)(void *dst, unsigned int size, const void *unsafe_ptr) = (void *)112;
static long (*bpf_probe_read_kernel_str)(void *dst, unsigned int size, const void *unsafe_ptr) = (void *)115;
static long (*bpf_probe_read_user_str)(void *dst, unsigned int size, const void *unsafe_ptr) = (void *)114;
static long (*bpf_probe_read)(void *dst, unsigned int size, const void *unsafe_ptr) = (void *)4; /* legacy */

/* skb / socket */
static unsigned long long (*bpf_get_socket_cookie)(void *ctx) = (void *)46;
static unsigned int (*bpf_get_socket_uid)(void *ctx) = (void *)47;
static long (*bpf_skb_load_bytes)(void *ctx, unsigned int offset, void *to, unsigned int len) = (void *)26;
static long (*bpf_skb_load_bytes_relative)(void *ctx, unsigned int offset, void *to, unsigned int len, unsigned int start_header) = (void *)68;

/* signals */
static long (*bpf_send_signal)(unsigned int sig) = (void *)109;
static long (*bpf_send_signal_thread)(unsigned int sig) = (void *)117;

/* misc */
static unsigned int (*bpf_get_prandom_u32)(void) = (void *)7;

/* CO-RE read macro: relocations resolved against running kernel BTF. */
#define CORE(expr) __builtin_preserve_access_index(expr)

/* Strlen for NUL-terminated strings with hard bound (verifier friendly). */
static __always_inline unsigned int dbg_strnlen(const char *s, unsigned int max)
{
        for (unsigned int i = 0; i < max; i++) {
                if (s[i] == '\0')
                        return i;
        }
        return max;
}

/* Case-insensitive single char compare. */
static __always_inline int dbg_ci_eq(char a, char b)
{
	/* branchless ASCII case-fold: collapses only pairs that
	 * differ in bit 5 (A-Z vs a-z); SQL keywords contain no
	 * other such pair. Keeps the verifier per-path jump count
	 * far below the 8192 limit. */
	return (a | 0x20) == (b | 0x20);
}


#define DBG_NEEDLE_MAX 32        /* longest needle accepted          */
#define DBG_HAY_MAX     96       /* max haystack bytes inspected     */

static DBG_FORCE_INLINE int dbg_contains_ci(const char *hay, unsigned int hay_len,
                                           const char *needle, unsigned int needle_len)
{
    unsigned int i, j, diff;
    __u32 first;

    if (needle_len == 0 || needle_len > DBG_NEEDLE_MAX || hay_len < needle_len)
        return 0;
    if (hay_len > DBG_HAY_MAX)
        hay_len = DBG_HAY_MAX;
    first = (__u32)(__u8)needle[0] | 0x20u;
    for (i = 0; i + needle_len <= hay_len; i++) {
        __u8 c0 = (__u8)hay[i];

        if (c0 == '\0')             /* NUL-terminated: stop the scan */
            break;
        if (((__u32)c0 | 0x20u) != first)
            continue;
        diff = 0;
        for (j = 1; j < needle_len; j++) {
            __u32 a = (__u32)(__u8)hay[i + j] | 0x20u;
            __u32 b = (__u32)(__u8)needle[j] | 0x20u;

            diff |= a ^ b;
        }
        if (diff == 0)
            return 1;
    }
    return 0;
}

#endif /* __DBGUARD_HELPERS_H */
