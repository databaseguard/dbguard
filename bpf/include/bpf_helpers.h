/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * Minimal bpf_helpers.h - SEC/map macros (vendored, self-contained build).
 * Canonical definitions live in libbpf <bpf/bpf_helpers.h>; this vendored copy
 * keeps DBGuard compilable with only clang + kernel headers installed.
 */
#ifndef __DBGUARD_BPF_HELPERS_H
#define __DBGUARD_BPF_HELPERS_H

#define SEC(NAME) __attribute__((section(NAME), used))

#ifndef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#endif
#ifndef __weak
#define __weak __attribute__((weak))
#endif
#define __hidden __attribute__((visibility("hidden")))

/* Map definition macros used by libbpf-style map declarations. */
#define __uint(name, val)  int (*name)[val]
#define __type(name, val)  typeof(val) *name
#define __cnt(name, val)   int (*const name)[val]

/* Licensing boilerplate: every DBGuard object defines this. */
#define DBGUARD_LICENSE "GPL"

/* Memory barrier hints. */
#define barrier()   __asm__ __volatile__("": : :"memory")
#define barrier_var(var) asm volatile("" : "+r"(var) : : "memory")

#if defined(__HAS_BUILTIN_EXPECT__) || defined(__GNUC__)
#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#else
#define likely(x) (x)
#define unlikely(x) (x)
#endif

#endif /* __DBGUARD_BPF_HELPERS_H */
