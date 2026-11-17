/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
 * dbguard/pii.h - in-kernel PII pre-scan for captured queries.
 *
 * The kernel side performs a cheap, bounded heuristic pass over every
 * audited SQL string (see audit.bpf.c) and raises DBG_QF_* flag bits in the
 * query event. User space (internal/pii) re-runs the full detector suite on
 * the same text with real regexes; the kernel flags act as a fast pre-filter
 * so the pipeline can prioritise likely-PII traffic without buffering.
 *
 * Verifier safety: every loop is constant-bounded (<= 512) and every
 * sub-check reads a fixed, in-range index. dbg_scan_pii clamps its input
 * length to DBG_PII_MAX_SCAN so callers may pass raw buffer sizes.
 */
#ifndef __DBGUARD_PII_H
#define __DBGUARD_PII_H

#include "dbguard/common.h"

/* Hard bounds - constant for the verifier, mirrored by the loop guards. */
#define DBG_PII_MAX_SCAN   96	/* was 512: verifier state explosion in the tokenizer */	/* maximum characters inspected            */
#define DBG_PII_MAX_CC     19	/* longest card-like digit run considered  */
#define DBG_PII_MIN_DIGITS 12	/* run length that flags DBG_QF_PII_DIGITS */
#define DBG_PII_TOKEN_MIN  20	/* secret-like token minimum length        */
#define DBG_PII_RUN_CAP    (DBG_PII_MAX_CC + 1) /* run_len cap; hitting it means >= MAX_CC */

/* Token class bits used by the secret-like heuristic. */
#define DBG_TOK_LOWER 0x1
#define DBG_TOK_UPPER 0x2
#define DBG_TOK_DIGIT 0x4
#define DBG_TOK_OTHER 0x8

static __always_inline int dbg_is_digit(char c)
{
	return c >= '0' && c <= '9';
}

/* Standard Luhn checksum over `len` digit characters. len must be a
 * compile-time constant at every call site (round19 calls pass 15/16) so
 * the loop fully unrolls and the double-step folds to lane arithmetic.
 * Callers guarantee every byte is '0'..'9', so there is no per-digit
 * validation branch (that branch multiplied the verifier state count). */
static DBG_FORCE_INLINE int dbg_luhn(const char *digits, int len)
{
	int sum = 0;
	int dbl = 0;   /* rightmost digit is the check digit: not doubled */
	int i;

	if (len < 2 || len > DBG_PII_MAX_CC)
		return 0;
	for (i = len - 1; i >= 0; i--) {
		int d = digits[i] - '0';
		int d2 = d << 1;

		/* branchless "subtract 9 if > 9": d2 is 0..18, so d2 >> 4 is
		 * exactly the carry bit. Keeps every lane comparison-free. */
		d2 -= (d2 >> 4) * 9;
		sum += dbl ? d2 : d;
		dbl = !dbl;
	}
	/* unsigned: the BPF backend rejects signed div/mod. */
	return ((__u32)sum % 10u) == 0;
}

/* Flush one finished digit run occupying [run, run + run_len).
 * round19: Luhn only runs for exact card lengths 15/16 (Visa/MC/Amex/
 * Discover). run_len is capped at DBG_PII_RUN_CAP by the scanner, so a
 * value of 20 means "20 or more" and correctly skips Luhn -- the old
 * code tested 13..19, which fed the verifier 7 unrolled checksum bodies
 * per flush position. User space re-runs the real detector anyway; the
 * kernel flag is a pre-filter. */
static DBG_FORCE_INLINE void dbg_pii_flush_run(const char *run,
					       unsigned int run_len,
					       __u64 *flags)
{
	if (run_len >= DBG_PII_MIN_DIGITS)
		*flags |= DBG_QF_PII_DIGITS;
	if (run_len == 15) {
		if (dbg_luhn(run, 15))
			*flags |= DBG_QF_LUHN_HIT;
	} else if (run_len == 16) {
		if (dbg_luhn(run, 16))
			*flags |= DBG_QF_LUHN_HIT;
	}
}

/* Bounded PII pre-scan of s[0..DBG_PII_MAX_SCAN). s must be NUL-terminated
 * and zero-padded past the terminator for the whole window (callers pass a
 * ringbuf field that was memset before probe_read_str). Sets DBG_QF_* bits
 * into *flags_out (previous contents replaced). Returns 1 when any flag
 * was raised.
 */
static __always_inline int dbg_scan_pii(const char *s, __u64 *flags_out)
{
	__u64 flags = 0;
	unsigned int i, k;

	if (flags_out)
		*flags_out = 0;
	if (!s)
		return 0;

	/* DDL keywords and bulk-select marker (constant window). */
	if (dbg_contains_ci(s, DBG_PII_MAX_SCAN, "DROP", 4) ||
	    dbg_contains_ci(s, DBG_PII_MAX_SCAN, "ALTER", 5) ||
	    dbg_contains_ci(s, DBG_PII_MAX_SCAN, "TRUNCATE", 8))
		flags |= DBG_QF_DDL;
	if (dbg_contains_ci(s, DBG_PII_MAX_SCAN, "SELECT *", 8))
		flags |= DBG_QF_BULK_SELECT;

	/* pass 1: digit runs. State: run_len only. The run start is
	 * i - run_len at flush time, so no second variable is carried. */
	{
		unsigned int run_len = 0;

		for (i = 0; i < DBG_PII_MAX_SCAN; i++) {
			char c = s[i];

			if (dbg_is_digit(c)) {
				if (run_len < DBG_PII_RUN_CAP)
					run_len++;
				continue;
			}
			if (run_len)
				dbg_pii_flush_run(s + i - run_len, run_len,
						  &flags);
			run_len = 0;
			if (c == '\0')
				break;
		}
		if (run_len)
			dbg_pii_flush_run(s + DBG_PII_MAX_SCAN - run_len,
					  run_len, &flags);
	}

	/* pass 2: SSN window check at every '-'. Reads are guarded to stay
	 * inside [0, DBG_PII_MAX_SCAN); zero padding makes bytes past the
	 * string read as NUL, i.e. non-digit boundaries, exactly like the
	 * old i+8 >= n short-circuit. */
	for (i = 0; i < DBG_PII_MAX_SCAN; i++) {
		if (s[i] != '-')
			continue;
		if (i < 3 || i + 7 >= DBG_PII_MAX_SCAN)
			continue;
		if (dbg_is_digit(s[i - 3]) && dbg_is_digit(s[i - 2]) &&
		    dbg_is_digit(s[i - 1]) && dbg_is_digit(s[i + 1]) &&
		    dbg_is_digit(s[i + 2]) && s[i + 3] == '-' &&
		    dbg_is_digit(s[i + 4]) && dbg_is_digit(s[i + 5]) &&
		    dbg_is_digit(s[i + 6]) && dbg_is_digit(s[i + 7]) &&
		    (i < 4 || !dbg_is_digit(s[i - 4])) &&
		    (i + 8 >= DBG_PII_MAX_SCAN ||
		     !dbg_is_digit(s[i + 8])))
			flags |= DBG_QF_SSN_LIKE;
	}

	/* pass 3: secret-like token window [i-19, i]. */
	for (i = DBG_PII_TOKEN_MIN - 1; i < DBG_PII_MAX_SCAN; i++) {
		__u8 classes = 0;
		__u8 bad = 0;

		for (k = 0; k < DBG_PII_TOKEN_MIN; k++) {
			char c = s[i - (DBG_PII_TOKEN_MIN - 1) + k];

			if (c == ' ' || c == '\t' || c == '\n' ||
			    c == '\r' || c == '\0')
				bad = 1;
			else if (dbg_is_digit(c))
				classes |= DBG_TOK_DIGIT;
			else if (c >= 'a' && c <= 'z')
				classes |= DBG_TOK_LOWER;
			else if (c >= 'A' && c <= 'Z')
				classes |= DBG_TOK_UPPER;
			else
				classes |= DBG_TOK_OTHER;
		}
		if (!bad && __builtin_popcount(classes) >= 2)
			flags |= DBG_QF_SECRET_LIKE;
	}

	if (flags_out)
		*flags_out = flags;
	return flags != 0;
}

#endif /* __DBGUARD_PII_H */
