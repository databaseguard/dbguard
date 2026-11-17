/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * dbguard/min_compat.h - minimal CO-RE kernel struct definitions.
 *
 * DBGuard reads a handful of kernel objects (sockets, dentries, files,
 * binprm) without depending on kernel development headers. The structs
 * below are SMALL LOCAL COPIES carrying only the fields we touch; every
 * struct is annotated with so all
 * member accesses emit BPF CO-RE relocations and are corrected against the
 * running kernel's BTF at load time. That keeps the offsets portable across
 * kernel versions and configurations (KASAN/lockdep shift struct sock etc.).
 *
 * UAPI structs (struct __sk_buff, struct xdp_md, struct sk_msg_md, ...) are
 * NOT redefined here - they come from <linux/bpf.h>.
 */
#ifndef __DBGUARD_MIN_COMPAT_H
#define __DBGUARD_MIN_COMPAT_H

#include <stddef.h>  /* NULL */
#include <linux/types.h>
#include "bpf_helpers.h"
#include "dbguard/helpers.h"

/* errno values returned by the LSM enforcement hooks (rids/tenant). The BPF
 * target is freestanding - no libc <errno.h> - and <linux/bpf.h> does not
 * pull these in, so define the canonical UAPI values here. Guarded so a
 * kernel header that already provides them does not clash. A negative return
 * from an lsm/* hook denies the operation (e.g. -EPERM on bprm_check kills
 * the exec; -EACCES on file_open blocks the open). */
#ifndef EPERM
#define EPERM  1  /* Operation not permitted */
#endif
#ifndef EACCES
#define EACCES 13 /* Permission denied */
#endif

/* ---- socket ------------------------------------------------------------
 * Mirrors the head of kernel's struct sock / struct sock_common. Field
 * byte orders matter and are called out on each member:
 *   skc_daddr     foreign IPv4, NETWORK order
 *   skc_rcv_saddr local  IPv4, NETWORK order
 *   skc_dport     foreign port, NETWORK order
 *   skc_num       local port,   HOST order
 *   skc_family    AF_INET / AF_INET6
 */
struct dbg_sock_common {
        __be32 skc_daddr;
        __be32 skc_rcv_saddr;
__u32 skc_hash;	/* kernel sock_common @8: union { u32 hash; u16 u16hashes[2]; } */
        __be16 skc_dport;
        __u16 skc_num;
        __u32 skc_family;
} ;

struct sock {
        struct dbg_sock_common __sk_common;
} ;

/* ---- path / file -------------------------------------------------------
 * Mirrors the used fields of struct qstr, struct dentry, struct path and
 * struct file. dbg_vfsmount is opaque: only ever referenced by pointer.
 */
struct dbg_qstr {
        const unsigned char *name;
        __u32 len;
} ;

struct dbg_dentry {
        struct dbg_dentry *d_parent;
        struct dbg_qstr d_name;
} ;

struct dbg_vfsmount;

struct dbg_path {
        struct dbg_vfsmount *mnt;
        struct dbg_dentry *dentry;
} ;

struct dbg_file {
        struct dbg_path f_path;
        unsigned int f_mode;    /* low bits carry FMODE_WRITE (0x2) etc. */
} ;

/* ---- linux_binprm (BPF LSM bprm_check_security argument) --------------- */
struct dbg_linux_binprm {
        const char *filename;
        struct dbg_file *file;
} ;

/* ---- tracepoint context ------------------------------------------------
 * Raw layout of a "sys_enter_*" tracepoint: the common prefix, an 8-byte
 * hole covering __syscall_nr + padding, then the syscall arguments. Only
 * args[0..3] are ever dereferenced (execve uses args[0]/args[1]; openat
 * uses args[1]/args[2]), keeping every read inside the context size.
 */
struct dbg_trace_enter {
        unsigned short common_type;
        unsigned char common_flags;
        unsigned char common_preempt_count;
        int common_pid;
        long id;
        unsigned long args[6];
};

/* ---- packet parsing aux -------------------------------------------------
 * 802.1Q VLAN tag as it appears on the wire after the Ethernet header.
 */
struct dbg_vlan_hdr {
        __be16 h_vlan_TCI;
        __be16 h_vlan_encapsulated_proto;
} __attribute__((packed));

/* ---- CO-RE field reads --------------------------------------------------
 * Reading kernel-object fields from kprobes/LSM contexts must use
 * bpf_probe_read_kernel(): the object pointer arrives as an opaque scalar
 * there, so a plain dereference would not verify. The address expression
 * inside __builtin_preserve_access_index() still emits the CO-RE field
 * relocation, so the offset is corrected against kernel BTF.
 *
 *   DBG_CORE_READ_INTO(&dst, ptr, a.b)   -> probe-read member into dst
 *   DBG_CORE_READ(ptr, a.b)              -> probe-read member by value
 */
#define DBG_CORE_READ_INTO(dst, ptr, member)                            \
        bpf_probe_read_kernel((dst), sizeof(*(dst)),                    \
                (const void *)__builtin_preserve_access_index(&(ptr)->member))

#define DBG_CORE_READ(ptr, member)                                      \
        ({                                                              \
                typeof((ptr)->member) __dbg_v;                          \
                __builtin_memset(&__dbg_v, 0, sizeof(__dbg_v));         \
                DBG_CORE_READ_INTO(&__dbg_v, (ptr), member);            \
                __dbg_v;                                                \
        })

/* ---- dbg_read_path ------------------------------------------------------
 * Reconstruct a "/bin/ps"-style path from a struct file: read
 * f_path.dentry, walk d_parent upwards (at most 5 levels) and emit the
 * components root-first into buf. Every component is read with a bounded,
 * NUL-terminated probe read; the output is NUL-terminated.
 *
 * Returns the path length (excluding NUL) or -1 on failure.
 */
static __always_inline int dbg_read_path(struct dbg_file *f, char *buf, int size)
{
        struct dbg_dentry *chain[5];
        struct dbg_dentry *d = NULL;
        char comp[64];
        int n = 0;
        int off = 0;
        int i;
        int j;

        if (!f || size <= 0)
                return -1;
        if (DBG_CORE_READ_INTO(&d, f, f_path.dentry) != 0 || !d)
                return -1;

        /* Collect the dentry chain, leaf first. Constant bound: 5 levels. */
        for (i = 0; i < 5; i++) {
                struct dbg_dentry *parent = NULL;

                if (!d)
                        break;
                chain[i] = d;
                n = i + 1;
                DBG_CORE_READ_INTO(&parent, d, d_parent);
                d = parent;
        }
        if (n == 0)
                return -1;

        /* Re-emit root -> leaf. Constant bounds: 5 components x 64 chars. */
        for (i = n - 1; i >= 0; i--) {
                const unsigned char *name = NULL;

                comp[0] = '\0';
                if (DBG_CORE_READ_INTO(&name, chain[i], d_name.name) != 0)
                        return -1;
                if (!name)
                        return -1;
                if (bpf_probe_read_kernel_str(comp, sizeof(comp), name) < 0)
                        return -1;
                if (off >= size - 1)
                        break;
                buf[off] = '/';
                off++;
                for (j = 0; j < 64; j++) {
                        char c = comp[j];

                        if (c == '\0')
                                break;
                        if (off >= size - 1)
                                break;
                        buf[off] = c;
                        off++;
                }
        }
        if (off == 0)
                return -1;
        buf[off] = '\0';
        return off;
}

#endif /* __DBGUARD_MIN_COMPAT_H */
