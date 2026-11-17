// Package pii - the PII detector: pattern matching over SQL statements and
// result samples, verification gating (checksums / entropy), finding
// emission with masked snippets and enforcement actions on the event.
package pii

import (
	"fmt"
	"log/slog"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/detect"
	"github.com/databaseguard/dbguard/internal/events"
)

// compile-time interface check: Detector satisfies the pipeline contract.
var _ detect.Detector = (*Detector)(nil)

// Default tuning values mirroring config.PIIConfig's operational defaults;
// used when the zero-value config is handed to New directly (tests/CLI).
const (
	defaultEntropyThreshold = 4.5
	defaultMaxScanLen       = 8192
)

// Detector scans SQL statements and result samples for PII and credentials.
// It is immutable after construction and safe for concurrent use.
type Detector struct {
	patterns         []*Pattern
	entropyThreshold float64
	maxScanLen       int
	redact           bool
	alertOnly        bool
	log              *slog.Logger
}

// New builds a PII detector from cfg. When cfg.Patterns names a subset of
// the built-in registry only those patterns are active; an empty list
// selects every built-in. Names listed in DisabledPatterns are removed.
// New fails when an explicit pattern list resolves to nothing.
func New(cfg config.PIIConfig, log *slog.Logger) (*Detector, error) {
	if log == nil {
		log = slog.Default()
	}
	var pats []*Pattern
	if len(cfg.Patterns) > 0 {
		pats = builtinByName(cfg.Patterns)
		if len(pats) == 0 {
			return nil, fmt.Errorf("pii: pattern selection %v matched no known pattern", cfg.Patterns)
		}
	} else {
		pats = allBuiltins()
	}
	if len(cfg.DisabledPatterns) > 0 {
		disabled := make(map[string]bool, len(cfg.DisabledPatterns))
		for _, n := range cfg.DisabledPatterns {
			disabled[n] = true
		}
		kept := make([]*Pattern, 0, len(pats))
		for _, p := range pats {
			if !disabled[p.Name] {
				kept = append(kept, p)
			}
		}
		pats = kept
	}

	threshold := cfg.EntropyThreshold
	if threshold <= 0 {
		threshold = defaultEntropyThreshold
	}
	scanLen := cfg.MaxScanLen
	if scanLen <= 0 {
		scanLen = defaultMaxScanLen
	}

	return &Detector{
		patterns:         pats,
		entropyThreshold: threshold,
		maxScanLen:       scanLen,
		redact:           cfg.Redact,
		alertOnly:        cfg.AlertOnly,
		log:              log,
	}, nil
}

// Name implements detect.Detector.
func (d *Detector) Name() string { return "pii" }

// Evaluate scans the event's SQL text and, when present, the
// "result_sample" metadata value. On hits it reclassifies the event as
// EvPIIHit, bumps severity to the worst matched pattern severity, requests
// an alert and - unless cfg.AlertOnly - adds deny+mask enforcement actions.
func (d *Detector) Evaluate(ev *events.Event) []events.Finding {
	if ev == nil {
		return nil
	}
	findings := d.InspectText(clampLen(ev.SQL, d.maxScanLen))
	if sample := ev.MetaGet("result_sample"); sample != "" {
		findings = append(findings, d.InspectText(clampLen(sample, d.maxScanLen))...)
	}
	if len(findings) == 0 {
		return nil
	}

	worst := events.SevInfo
	for _, p := range d.patterns {
		kind := "pii." + p.Name
		for _, f := range findings {
			if f.Kind == kind && p.Severity.Order() > worst.Order() {
				worst = p.Severity
				break
			}
		}
	}

	ev.Type = events.EvPIIHit
	if worst.Order() > ev.Severity.Order() {
		ev.Severity = worst
	}
	ev.AddAction(events.ActAlert)
	if !d.alertOnly {
		ev.AddAction(events.ActDeny)
		ev.AddAction(events.ActMask)
	}
	if d.log != nil {
		d.log.Debug("pii: findings", "kinds", len(findings), "worst", string(worst))
	}
	return findings
}

// InspectText runs every active pattern over text and returns the findings.
// It is the entry point for the CLI test-pii command and for the audit
// redaction path; the returned Start/End offsets index into text.
func (d *Detector) InspectText(text string) []events.Finding {
	fs, _ := d.scan(text)
	return fs
}

// Redactor returns a closure suitable for log/audit writers: it detects PII
// in the input and splices masked snippets over the raw spans via
// RedactFindings, returning the input unchanged when nothing matches.
// Callers typically wire this when cfg.Redact is set.
func (d *Detector) Redactor() func(string) string {
	return func(text string) string {
		fs := d.InspectText(text)
		if len(fs) == 0 {
			return text
		}
		return RedactFindings(text, fs)
	}
}

// scan runs all patterns over one text buffer, returning the findings and
// the worst severity among matched patterns.
func (d *Detector) scan(text string) ([]events.Finding, events.Severity) {
	if text == "" {
		return nil, events.SevInfo
	}
	var (
		out   []events.Finding
		spans [][2]int // accepted spans, for the overlap guard
		worst = events.SevInfo
	)
	for _, p := range d.patterns {
		for _, loc := range p.Regex.FindAllStringIndex(text, -1) {
			start, end := loc[0], loc[1]
			match := text[start:end]
			if !d.accept(p, match) || overlaps(spans, start, end) {
				continue
			}
			spans = append(spans, [2]int{start, end})
			out = append(out, events.Finding{
				Kind:       "pii." + p.Name,
				Detail:     p.Description,
				Confidence: p.Confidence,
				Snippet:    Mask(match, p.MaskMode),
				Start:      start,
				End:        end,
			})
			if p.Severity.Order() > worst.Order() {
				worst = p.Severity
			}
		}
	}
	return out, worst
}

// accept applies the pattern's verification gate: explicit Verify (Luhn,
// IBAN, octet ranges) wins; secret-like patterns without Verify require the
// credential payload's Shannon entropy to reach the configured threshold.
func (d *Detector) accept(p *Pattern, match string) bool {
	if p.Verify != nil {
		return p.Verify(match)
	}
	if p.entropyGate {
		return Shannon(secretPayload(match)) >= d.entropyThreshold
	}
	return true
}

// overlaps reports whether [start,end) intersects any accepted span.
func overlaps(spans [][2]int, start, end int) bool {
	for _, s := range spans {
		if start < s[1] && end > s[0] {
			return true
		}
	}
	return false
}

// clampLen truncates s to at most n bytes.
func clampLen(s string, n int) string {
	if n > 0 && len(s) > n {
		return s[:n]
	}
	return s
}
