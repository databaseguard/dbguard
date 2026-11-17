// Package sqli - the signature catalogue.
//
// Each Signature is a cheap predicate over a scanCtx (raw text, lowercased
// text, token-normalized text). Signatures never see interpolated input:
// normalized strips comments and quoting variance so "UN/**/ION SELECT" and
// "UNION\tSELECT" both normalize to comparable shapes.
package sqli

import (
	"regexp"
	"strings"

	"github.com/databaseguard/dbguard/internal/events"
)

// tautologyRe finds a comparison guarded by OR/AND over the normalized
// (comment-free, single-spaced, lowercased) token stream, capturing both
// sides. Go's RE2 has no back-references, so self-equality (X = X) is checked
// in isTautology rather than in the pattern. Matches:
//
//	or 7 = 7      and 1=1      or 'x' = 'x'      or "a"="a"      or col = col
var tautologyRe = regexp.MustCompile(
	`\b(?:or|and)\s+('?"?[a-z0-9_]+'?"?)\s*=\s*('?"?[a-z0-9_]+'?"?)`)

// isTautology reports whether the normalized stream contains an OR/AND guarded
// self-equal comparison (always true), e.g. "or 7=7". Quoting is normalized so
// 'x'='x' and "x"="x" count; the two operands must be identical after trimming
// surrounding quotes.
func isTautology(normalized string) bool {
	for _, m := range tautologyRe.FindAllStringSubmatch(normalized, -1) {
		lhs := strings.Trim(m[1], `'"`)
		rhs := strings.Trim(m[2], `'"`)
		if lhs == rhs {
			return true
		}
	}
	return false
}

// scanCtx is the immutable per-statement analysis context handed to every
// signature test.
type scanCtx struct {
	raw        string  // original statement
	lower      string  // strings.ToLower(raw)
	normalized string  // comment-free tokens joined by single spaces, lowercased
	tokens     []Token // lexical tokens of raw
}

// Signature is one SQL injection detector: an identifier, presentation
// metadata, a confidence Weight and a predicate. Engines, when non-empty,
// restrict the signature to specific database engines.
type Signature struct {
	ID       string
	Name     string
	Severity events.Severity
	Weight   float64
	Engines  []string
	Test     func(c *scanCtx) bool
}

// has reports whether the lowercased raw text contains s.
func (c *scanCtx) has(s string) bool { return strings.Contains(c.lower, s) }

// hasWord reports whether the normalized token stream contains s as a
// space-delimited phrase (padding guards against identifier substrings,
// e.g. "or true" inside "enabled_or_true").
func (c *scanCtx) hasWord(s string) bool {
	return strings.Contains(" "+c.normalized+" ", " "+s+" ")
}

// newScanCtx builds the analysis context for one statement.
func newScanCtx(sql string) *scanCtx {
	toks := Tokenize(sql)
	var b strings.Builder
	b.Grow(len(sql) + 8)
	for _, t := range toks {
		if t.Kind == TokComment {
			continue // normalized is comment-free
		}
		b.WriteString(strings.ToLower(t.Text))
		b.WriteByte(' ')
	}
	return &scanCtx{
		raw:        sql,
		lower:      strings.ToLower(sql),
		normalized: strings.TrimSpace(b.String()),
		tokens:     toks,
	}
}

// allSignatures returns the signature catalogue in evaluation order. Order
// matters only for finding presentation; scoring is order-independent.
func allSignatures() []*Signature {
	return []*Signature{
		{
			ID: "sqli.tautology", Name: "boolean tautology (OR/AND always-true)",
			Severity: events.SevHigh, Weight: 1.0,
			Test: func(c *scanCtx) bool {
				// Fast literal paths first (cheap, cover the classic shapes).
				if c.has(" or true") || c.has("' or '1'='1") || c.has("'1'='1") ||
					c.hasWord("or true") {
					return true
				}
				// General case: an OR/AND followed by a self-equal comparison
				// that is always true - N=N (same number), 'x'='x' (same
				// string) or col=col - catching arbitrary constants (7=7,
				// 99=99), not just the literal 1=1. Checked over the
				// comment-free normalized stream AND the raw lowercased text,
				// so comment/space evasion ("or/**/5=5") and payloads with
				// unbalanced quotes ("x' or 'abc'='abc") are both covered.
				return isTautology(c.normalized) || isTautology(c.lower)
			},
		},
		{
			ID: "sqli.union_select", Name: "UNION SELECT column extraction",
			Severity: events.SevCritical, Weight: 1.0,
			Test: func(c *scanCtx) bool {
				return c.hasWord("union select") || c.hasWord("union all select") ||
					c.has("union select") || c.has("union all select")
			},
		},
		{
			ID: "sqli.stacked_queries", Name: "stacked second query",
			Severity: events.SevCritical, Weight: 1.0,
			Test: func(c *scanCtx) bool {
				for _, kw := range []string{"drop", "delete", "truncate", "shutdown",
					"insert", "update", "alter", "create", "exec"} {
					if c.has("; "+kw) || c.hasWord("; "+kw) {
						return true
					}
				}
				return false
			},
		},
		{
			ID: "sqli.comment_after_quote", Name: "quote followed by comment (truncation)",
			Severity: events.SevHigh, Weight: 0.9,
			Test: func(c *scanCtx) bool {
				return c.has("'--") || c.has("'#") || c.has("'/*") ||
					c.has(`"--`) || c.has(`"#`)
			},
		},
		{
			ID: "sqli.time_based", Name: "time-based blind injection",
			Severity: events.SevCritical, Weight: 1.0,
			Test: func(c *scanCtx) bool {
				return c.has("sleep(") || c.has("pg_sleep(") || c.has("pg_sleep_for") ||
					c.has("pg_sleep_until") || c.has("benchmark(") ||
					c.has("waitfor delay") || c.has("dbms_lock.sleep")
			},
		},
		{
			ID: "sqli.error_based", Name: "error-based extraction",
			Severity: events.SevHigh, Weight: 0.95,
			Test: func(c *scanCtx) bool {
				return c.has("extractvalue(") || c.has("updatexml(") ||
					c.has("floor(rand") || c.has("xmltype(") ||
					(c.has("convert(") && c.has(" using "))
			},
		},
		{
			ID: "sqli.boolean_blind", Name: "boolean/character blind probing",
			Severity: events.SevMedium, Weight: 0.6,
			Test: func(c *scanCtx) bool {
				for _, kw := range []string{"and ascii(", "or ascii(", "and substr(",
					"or substr(", "and mid(", "or mid(", "and if(", "or if(",
					"and length(", "order by 100"} {
					if c.has(kw) {
						return true
					}
				}
				return false
			},
		},
		{
			ID: "sqli.out_of_band", Name: "out-of-band exfiltration channel",
			Severity: events.SevCritical, Weight: 1.0,
			Test: func(c *scanCtx) bool {
				return c.has("utl_http") || c.has("httprequest") ||
					c.has("utl_inaddr") || c.has("load_file(concat")
			},
		},
		{
			ID: "sqli.filesystem", Name: "server filesystem access (MySQL)",
			Severity: events.SevCritical, Weight: 1.0, Engines: []string{"mysql"},
			Test: func(c *scanCtx) bool {
				return c.has("load_file(") || c.has("into outfile") || c.has("into dumpfile")
			},
		},
		{
			ID: "sqli.pg_copy", Name: "server filesystem / program exec (PostgreSQL)",
			Severity: events.SevCritical, Weight: 1.0, Engines: []string{"postgres"},
			Test: func(c *scanCtx) bool {
				return c.has("from program") || c.has("pg_read_file") ||
					c.has("pg_read_binary_file") || c.has("pg_read_server_files") ||
					c.has("pg_execute_server_program") || c.has("lo_import") || c.has("lo_export")
			},
		},
		{
			ID: "sqli.privesc", Name: "role / privilege escalation",
			Severity: events.SevHigh, Weight: 0.9,
			Test: func(c *scanCtx) bool {
				return c.hasWord("set role") || c.hasWord("set session authorization") ||
					c.hasWord("create extension") || c.hasWord("alter system") ||
					c.hasWord("alter role") || c.hasWord("create role") ||
					c.has("grant all") || c.has("superuser")
			},
		},
		{
			ID: "sqli.dangerous_procs", Name: "dangerous server procedure",
			Severity: events.SevHigh, Weight: 0.95,
			Test: func(c *scanCtx) bool {
				return c.has("xp_cmdshell") || c.has("sp_configure") ||
					c.has("exec master") || c.hasWord("system (") || c.hasWord("shell (")
			},
		},
		{
			ID: "sqli.hex_encoding", Name: "hex-encoded quote or payload",
			Severity: events.SevHigh, Weight: 0.75,
			Test: func(c *scanCtx) bool {
				return c.has("0x27") || c.has("0x3d") || c.has("char(39)") || c.has("chr(39)")
			},
		},
		{
			ID: "sqli.url_encoding", Name: "URL-encoded quote in SQL text",
			Severity: events.SevHigh, Weight: 0.75,
			Test: func(c *scanCtx) bool {
				return c.has("%27") || c.has("%2527")
			},
		},
		{
			ID: "sqli.null_byte", Name: "null byte / %00 truncation",
			Severity: events.SevCritical, Weight: 0.9,
			Test: func(c *scanCtx) bool {
				return strings.IndexByte(c.raw, 0) >= 0 || c.has("%00")
			},
		},
		{
			ID: "sqli.meta_leak", Name: "system catalogue probing",
			Severity: events.SevMedium, Weight: 0.6,
			Test: func(c *scanCtx) bool {
				return c.has("information_schema") || c.has("pg_catalog") ||
					c.has("mysql.user") || c.has("sys.x$") ||
					c.has("performance_schema") || c.has("sqlite_master")
			},
		},
		{
			ID: "sqli.obfuscated_comment", Name: "keyword split by inline comment",
			Severity: events.SevHigh, Weight: 0.9,
			Test: sigObfuscatedComment,
		},
		{
			ID: "sqli.like_injection", Name: "LIKE clause quote injection",
			Severity: events.SevMedium, Weight: 0.6,
			Test: func(c *scanCtx) bool {
				return c.has("' like '") || c.has("%' and '%")
			},
		},
		{
			ID: "sqli.order_by_probe", Name: "ORDER BY column-number probe with comment",
			Severity: events.SevMedium, Weight: 0.6,
			Test: sigOrderByProbe,
		},
		{
			ID: "sqli.ddl_drop", Name: "destructive DDL",
			Severity: events.SevHigh, Weight: 0.85,
			Test: func(c *scanCtx) bool {
				return c.hasWord("drop table") || c.hasWord("drop database") ||
					c.hasWord("drop schema") || c.hasWord("drop user") ||
					c.hasWord("truncate table")
			},
		},
		{
			ID: "sqli.grant_dangerous", Name: "privilege grant escalation",
			Severity: events.SevHigh, Weight: 0.9,
			Test: func(c *scanCtx) bool {
				return c.hasWord("grant all privileges") || c.has("with grant option") ||
					c.hasWord("grant all")
			},
		},
		{
			ID: "sqli.bulk_unbounded", Name: "unbounded SELECT * (dump-shaped, low confidence)",
			Severity: events.SevLow, Weight: 0.3,
			Test: func(c *scanCtx) bool {
				return c.hasWord("select *") && c.has(" from ") &&
					!c.has(" where ") && !c.has(" limit ")
			},
		},
		{
			ID: "sqli.escape_bypass", Name: "backslash-escaped quote (charset/addslashes bypass)",
			Severity: events.SevMedium, Weight: 0.6,
			Test: func(c *scanCtx) bool {
				return c.has(`\'`) || c.has(`\"`)
			},
		},
	}
}

// sigObfuscatedComment flags keywords reassembled across inline comments:
// "UN/**/ION SELECT" normalizes to "un ion select" (no "union"), but the
// comment-stripped, space-joined stream still contains it.
func sigObfuscatedComment(c *scanCtx) bool {
	if !strings.Contains(c.raw, "/*") && !strings.Contains(c.raw, "--") {
		return false
	}
	squashed := strings.ReplaceAll(c.normalized, " ", "")
	for _, kw := range []string{"union", "select", "insert", "update", "delete", "drop", "sleep", "benchmark"} {
		if !strings.Contains(c.normalized, kw) && strings.Contains(squashed, kw) {
			return true
		}
	}
	return false
}

// sigOrderByProbe flags "ORDER BY <number> --" style column-count probing.
func sigOrderByProbe(c *scanCtx) bool {
	idx := strings.Index(c.lower, "order by")
	if idx < 0 {
		return false
	}
	rest := strings.TrimLeft(c.lower[idx+len("order by"):], " \t")
	n := 0
	for n < len(rest) && rest[n] >= '0' && rest[n] <= '9' {
		n++
	}
	if n == 0 {
		return false
	}
	tail := strings.TrimLeft(rest[n:], " \t")
	return strings.HasPrefix(tail, "--") || strings.HasPrefix(tail, "#") ||
		strings.HasPrefix(tail, "/*")
}
