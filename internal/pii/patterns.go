// Package pii detects personally identifiable information (PII) and
// credential material inside database statements and result samples. It is
// the user-space half of DBGuard feature 1 (PII leak prevention): the eBPF
// layer tags candidate flows, while this package performs precise pattern
// matching, verification (Luhn checksums, IBAN mod-97, entropy analysis)
// and configurable masking of every detected span.
//
// The built-in registry covers payment cards, US social security numbers,
// emails, international phone numbers, IBANs, JWTs, cloud credentials,
// private-key blocks, generic API keys, literal passwords, IPv4 addresses
// and a low-confidence national-id heuristic. Deployment configs select
// subsets by name via config.PIIConfig.
package pii

import (
	"regexp"
	"strings"

	"github.com/databaseguard/dbguard/internal/events"
)

// MaskMode selects the masking strategy applied to a detected span.
type MaskMode int

const (
	// MaskKeepLast4 keeps the final four characters visible and masks the
	// rest (e.g. payment cards: ************1111).
	MaskKeepLast4 MaskMode = iota
	// MaskFull masks every character of the match.
	MaskFull
	// MaskHash replaces the match with the first 8 hex characters of its
	// SHA-256, preserving correlatability without revealing the value.
	MaskHash
)

// Pattern describes one detectable PII or secret shape.
type Pattern struct {
	// Name is the registry identifier ("credit_card", "ssn_us", ...).
	Name string
	// Description is a human-readable explanation used in finding details.
	Description string
	// Regex matches candidate spans; Verify may further validate them.
	Regex *regexp.Regexp
	// Severity is the severity applied to events when this pattern hits.
	Severity events.Severity
	// Confidence is the baseline confidence for hits (0.0 - 1.0).
	Confidence float64
	// Verify, when non-nil, validates a candidate match; a hit is only
	// reported when Verify passes - or, for entropy-gated patterns, when
	// the payload entropy reaches the configured threshold.
	Verify func(match string) bool
	// MaskMode selects how matches are masked in findings and redactions.
	MaskMode MaskMode

	// entropyGate marks loose "secret-like" patterns whose hits additionally
	// require payload Shannon entropy to reach the configured threshold.
	entropyGate bool
}

// b64Alphabet is the base64-ish character set used to isolate the credential
// payload of a secret-like match before entropy scoring.
const b64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/+="

// builtinPatterns is the built-in pattern registry. Entries are immutable
// after init; allBuiltins/builtinByName hand out pointers into this slice.
var builtinPatterns = []Pattern{
	{
		Name:        "credit_card",
		Description: "payment card number (13-19 digits, Luhn checksum)",
		Regex:       regexp.MustCompile(`\b\d(?:[ -]?\d){12,18}\b`),
		Severity:    events.SevHigh,
		Confidence:  0.95,
		Verify:      luhnValid,
		MaskMode:    MaskKeepLast4,
	},
	{
		Name:        "ssn_us",
		Description: "US social security number",
		Regex:       regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`),
		Severity:    events.SevHigh,
		Confidence:  0.9,
		MaskMode:    MaskFull,
	},
	{
		Name:        "email",
		Description: "email address",
		Regex:       regexp.MustCompile(`[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}`),
		Severity:    events.SevMedium,
		Confidence:  0.8,
		MaskMode:    MaskHash,
	},
	{
		Name:        "phone_intl",
		Description: "international phone number",
		Regex:       regexp.MustCompile(`\+\d{1,3}[-.\s]?\(?\d{1,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}`),
		Severity:    events.SevLow,
		Confidence:  0.6,
		MaskMode:    MaskFull,
	},
	{
		Name:        "iban",
		Description: "international bank account number (mod-97 checksum)",
		Regex:       regexp.MustCompile(`\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b`),
		Severity:    events.SevHigh,
		Confidence:  0.85,
		Verify:      ibanValid,
		MaskMode:    MaskKeepLast4,
	},
	{
		Name:        "jwt",
		Description: "JSON web token (three dot-separated base64 segments)",
		Regex:       regexp.MustCompile(`eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}`),
		Severity:    events.SevHigh,
		Confidence:  0.9,
		MaskMode:    MaskFull,
	},
	{
		Name:        "aws_access_key",
		Description: "AWS access key id (AKIA...)",
		Regex:       regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`),
		Severity:    events.SevHigh,
		Confidence:  0.95,
		MaskMode:    MaskKeepLast4,
	},
	{
		Name:        "aws_secret",
		Description: "AWS secret access key near context word",
		Regex:       regexp.MustCompile(`(?i)aws.{0,30}['"]?[A-Za-z0-9/+=]{40}`),
		Severity:    events.SevCritical,
		Confidence:  0.8,
		MaskMode:    MaskFull,
		entropyGate: true,
	},
	{
		Name:        "private_key_block",
		Description: "PEM private key block header",
		Regex:       regexp.MustCompile(`-----BEGIN(?: [A-Z0-9]+)* PRIVATE KEY-----`),
		Severity:    events.SevCritical,
		Confidence:  0.98,
		MaskMode:    MaskFull,
	},
	{
		Name:        "api_key_generic",
		Description: "generic API key/token/secret assignment",
		Regex:       regexp.MustCompile(`(?i)(?:api[_-]?key|token|secret)['"]?\s*[:=]\s*['"][A-Za-z0-9_\-]{16,64}`),
		Severity:    events.SevHigh,
		Confidence:  0.75,
		MaskMode:    MaskKeepLast4,
	},
	{
		Name:        "password_literal",
		Description: "hardcoded password literal",
		Regex:       regexp.MustCompile(`(?i)(?:password|passwd|pwd)\s*[:=]\s*['"][^'"]{6,}`),
		Severity:    events.SevMedium,
		Confidence:  0.7,
		MaskMode:    MaskFull,
	},
	{
		Name:        "ipv4",
		Description: "IPv4 address",
		Regex:       regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`),
		Severity:    events.SevLow,
		Confidence:  0.5,
		Verify:      validIPv4,
		MaskMode:    MaskHash,
	},
	{
		Name:        "national_id_generic",
		Description: "generic national id shape (secondary confidence)",
		Regex:       regexp.MustCompile(`\b\d{3}-?\d{4}-?\d{4}\b`),
		Severity:    events.SevLow,
		Confidence:  0.4,
		MaskMode:    MaskFull,
	},
}

// builtinIndex maps registry names onto entries for O(1) lookup/validation.
var builtinIndex = func() map[string]*Pattern {
	idx := make(map[string]*Pattern, len(builtinPatterns))
	for i := range builtinPatterns {
		idx[builtinPatterns[i].Name] = &builtinPatterns[i]
	}
	return idx
}()

// allBuiltins returns pointers to every built-in pattern in registry order.
func allBuiltins() []*Pattern {
	out := make([]*Pattern, len(builtinPatterns))
	for i := range builtinPatterns {
		out[i] = &builtinPatterns[i]
	}
	return out
}

// builtinByName resolves the given names against the registry, preserving
// request order and skipping unknown names. Callers that need to reject
// unknown names can compare the result length against len(names).
func builtinByName(names []string) []*Pattern {
	out := make([]*Pattern, 0, len(names))
	for _, name := range names {
		if p, ok := builtinIndex[name]; ok {
			out = append(out, p)
		}
	}
	return out
}

// secretPayload extracts the trailing run of base64-ish characters from a
// match: for secret-like patterns that run is the credential value whose
// Shannon entropy decides acceptance.
func secretPayload(match string) string {
	s := strings.TrimRight(match, "'\" \t")
	i := len(s)
	for i > 0 && strings.IndexByte(b64Alphabet, s[i-1]) >= 0 {
		i--
	}
	return s[i:]
}

// ibanValid validates an IBAN using the ISO 13616 mod-97 algorithm.
func ibanValid(s string) bool {
	s = strings.ToUpper(strings.ReplaceAll(s, " ", ""))
	if len(s) < 15 || len(s) > 34 {
		return false
	}
	rearranged := s[4:] + s[:4] // check digits move to the end
	rem := 0
	for i := 0; i < len(rearranged); i++ {
		c := rearranged[i]
		var v int
		switch {
		case c >= '0' && c <= '9':
			v = int(c - '0')
		case c >= 'A' && c <= 'Z':
			v = int(c-'A') + 10
		default:
			return false
		}
		if v < 10 {
			rem = (rem*10 + v) % 97
		} else {
			rem = (rem*100 + v) % 97
		}
	}
	return rem == 1
}

// validIPv4 reports whether s is four octets in 0-255.
func validIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if len(p) == 0 || len(p) > 3 {
			return false
		}
		n := 0
		for i := 0; i < len(p); i++ {
			if p[i] < '0' || p[i] > '9' {
				return false
			}
			n = n*10 + int(p[i]-'0')
		}
		if n > 255 {
			return false
		}
	}
	return true
}
