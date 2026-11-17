/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * bpf_tracing.h - minimal x86_64 + arm64 pt_regs accessors.
 * Vendored/self-contained; canonical version lives in libbpf.
 *
 * DBGuard programs declare probe handlers with the raw signature
 *     SEC("kprobe/tcp_sendmsg") int BPF_KPROBE(tcp_sendmsg, ...)
 * is NOT used here; instead use:
 *     SEC("kprobe/tcp_sendmsg") int on_tcp_sendmsg(struct pt_regs *ctx)
 * and fetch args with PT_REGS_PARM1(ctx) .. PT_REGS_PARM5(ctx),
 * return value with PT_REGS_RC(ctx).
 */
#ifndef __DBGUARD_BPF_TRACING_H
#define __DBGUARD_BPF_TRACING_H

#include "bpf_helpers.h"

#if defined(__TARGET_ARCH_x86)

struct pt_regs {
	unsigned long r15;
	unsigned long r14;
	unsigned long r13;
	unsigned long r12;
	unsigned long bp;
	unsigned long bx;
	unsigned long r11;
	unsigned long r10;
	unsigned long r9;
	unsigned long r8;
	unsigned long ax;
	unsigned long cx;
	unsigned long dx;
	unsigned long si;
	unsigned long di;
	unsigned long orig_ax;
	unsigned long ip;
	unsigned long cs;
	unsigned long flags;
	unsigned long sp;
	unsigned long ss;
};

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_PARM6(x) ((x)->r9)
#define PT_REGS_RC(x)    ((x)->ax)
#define PT_REGS_IP(x)    ((x)->ip)
#define PT_REGS_SP(x)    ((x)->sp)

#elif defined(__TARGET_ARCH_arm64)

struct pt_regs {
	union {
		struct {
			unsigned long regs[31];
			unsigned long sp;
			unsigned long pc;
			unsigned long pstate;
		};
		struct {
			unsigned long orig_x0;
			unsigned long syscallno;
			unsigned long unused0;
			unsigned long unused1;
		};
	};
};

#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_PARM4(x) ((x)->regs[3])
#define PT_REGS_PARM5(x) ((x)->regs[4])
#define PT_REGS_PARM6(x) ((x)->regs[5])
#define PT_REGS_RC(x)    ((x)->regs[0])
#define PT_REGS_IP(x)    ((x)->pc)
#define PT_REGS_SP(x)    ((x)->sp)

#else
#error "DBGuard BPF: define __TARGET_ARCH_x86 or __TARGET_ARCH_arm64"
#endif

#endif /* __DBGUARD_BPF_TRACING_H */
