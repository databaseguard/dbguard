/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * bpf_endian.h - byte-order helpers (vendored, self-contained build).
 */
#ifndef __DBGUARD_BPF_ENDIAN_H
#define __DBGUARD_BPF_ENDIAN_H

#include <asm/byteorder.h>

/* clang BPF backend: always be bpf_to_le host or use builtins below. */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define __bpf_ntohs(x) __builtin_bswap16(x)
#define __bpf_htons(x) __builtin_bswap16(x)
#define __bpf_ntohl(x) __builtin_bswap32(x)
#define __bpf_htonl(x) __builtin_bswap32(x)
#define __bpf_ntohll(x) __builtin_bswap64(x)
#define __bpf_htonll(x) __builtin_bswap64(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define __bpf_ntohs(x) (x)
#define __bpf_htons(x) (x)
#define __bpf_ntohl(x) (x)
#define __bpf_htonl(x) (x)
#define __bpf_ntohll(x) (x)
#define __bpf_htonll(x) (x)
#else
#error "Unsupported byte order"
#endif

#define bpf_ntohs(x) __bpf_ntohs(x)
#define bpf_htons(x) __bpf_htons(x)
#define bpf_ntohl(x) __bpf_ntohl(x)
#define bpf_htonl(x) __bpf_htonl(x)
#define bpf_ntohll(x) __bpf_ntohll(x)
#define bpf_htonll(x) __bpf_htonll(x)

#endif /* __DBGUARD_BPF_ENDIAN_H */
