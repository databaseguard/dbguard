// Package pii - masking strategies and redaction of detected spans.
//
// Mask turns a raw match into its redacted form according to the pattern's
// MaskMode; RedactFindings splices those masked snippets back into the
// original text so logs, audit records and API responses never carry raw
// PII/credential material.
package pii

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"

	"github.com/databaseguard/dbguard/internal/events"
)

// Mask applies the masking strategy mode to s.
//
//   - MaskKeepLast4 hides everything but the final four characters
//     ("************1111"); values shorter than four characters are masked
//     completely, since a partially visible short value is still revealing.
//   - MaskFull replaces every character with '*'.
//   - MaskHash replaces the value with the first 8 hex characters of its
//     SHA-256, keeping correlatability (join/group by) without disclosure.
//
// Unknown modes fall back to full masking (fail closed).
func Mask(s string, mode MaskMode) string {
	if s == "" {
		return ""
	}
	switch mode {
	case MaskKeepLast4:
		if len(s) >= 4 {
			return strings.Repeat("*", len(s)-4) + s[len(s)-4:]
		}
		return strings.Repeat("*", len(s))
	case MaskHash:
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:8])[:8]
	default:
		return strings.Repeat("*", len(s))
	}
}

// RedactFindings replaces every finding span [Start,End) in text with the
// finding's (already masked) Snippet and returns the redacted copy.
//
// Findings are consumed in order; spans are skipped when they are out of
// bounds, empty, or overlap a span that was already replaced, so a finding
// list produced by scan (which is ordered and non-overlapping) redacts
// exactly once per character. Offsets refer to the same text that produced
// the findings (byte offsets into the scanned SQL or result sample).
func RedactFindings(text string, fs []events.Finding) string {
	if text == "" || len(fs) == 0 {
		return text
	}
	var b strings.Builder
	b.Grow(len(text))
	last := 0 // first byte not yet written
	for _, f := range fs {
		if f.Start < last || f.Start < 0 || f.End > len(text) || f.Start >= f.End {
			continue // invalid or overlapping span: leave region untouched
		}
		b.WriteString(text[last:f.Start])
		b.WriteString(f.Snippet)
		last = f.End
	}
	b.WriteString(text[last:])
	return b.String()
}
