package pii

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mustDetector(t *testing.T, cfg config.PIIConfig) *Detector {
	t.Helper()
	d, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("pii.New: %v", err)
	}
	return d
}

func indexOfKind(fs []events.Finding, kind string) int {
	for i, f := range fs {
		if f.Kind == kind {
			return i
		}
	}
	return -1
}

// TestDetectorEvaluate covers the built-in pattern table end to end: the
// expected finding kind fires, the snippet is masked (evidence visible
// without the raw value) and the event is reclassified with enforcement
// actions.
func TestDetectorEvaluate(t *testing.T) {
	tests := []struct {
		name      string
		sql       string
		wantKind  string
		wantSub   string // substring required in the masked snippet
		wantNoSub string // substring forbidden in the masked snippet
		wantSev   events.Severity
	}{
		{
			name:      "credit card",
			sql:       "SELECT * FROM customers WHERE card = '4111111111111111'",
			wantKind:  "pii.credit_card",
			wantSub:   "1111",
			wantNoSub: "4111111111111111",
			wantSev:   events.SevHigh,
		},
		{
			name:      "ssn",
			sql:       "INSERT INTO people (ssn) VALUES ('123-45-6789')",
			wantKind:  "pii.ssn_us",
			wantNoSub: "123-45-6789",
			wantSev:   events.SevHigh,
		},
		{
			name:      "email",
			sql:       "SELECT * FROM contacts WHERE email = 'alice@example.com'",
			wantKind:  "pii.email",
			wantNoSub: "alice@example.com",
			wantSev:   events.SevMedium,
		},
		{
			name:      "jwt token",
			sql:       "SELECT * FROM sessions WHERE token = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'",
			wantKind:  "pii.jwt",
			wantNoSub: "eyJhbGciOiJIUzI1NiJ9",
			wantSev:   events.SevHigh,
		},
		{
			name:      "aws access key",
			sql:       "SELECT * FROM cfg WHERE key = 'AKIAIOSFODNN7EXAMPLE'",
			wantKind:  "pii.aws_access_key",
			wantSub:   "MPLE",
			wantNoSub: "AKIAIOSFODNN7EXAMPLE",
			wantSev:   events.SevHigh,
		},
		{
			name:      "password literal",
			sql:       "UPDATE users SET password = 'hunter2secret'",
			wantKind:  "pii.password_literal",
			wantNoSub: "hunter2secret",
			wantSev:   events.SevMedium,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			d := mustDetector(t, config.PIIConfig{})
			ev := &events.Event{Type: events.EvQueryAudit, Severity: events.SevInfo, SQL: tc.sql}
			fs := d.Evaluate(ev)
			idx := indexOfKind(fs, tc.wantKind)
			if idx < 0 {
				t.Fatalf("finding %s missing, got %+v", tc.wantKind, fs)
			}
			f := fs[idx]
			if tc.wantSub != "" && !strings.Contains(f.Snippet, tc.wantSub) {
				t.Fatalf("snippet %q missing %q", f.Snippet, tc.wantSub)
			}
			if tc.wantNoSub != "" && strings.Contains(f.Snippet, tc.wantNoSub) {
				t.Fatalf("snippet %q leaks raw value", f.Snippet)
			}
			if f.Confidence <= 0 || f.Confidence > 1 {
				t.Fatalf("confidence out of range: %v", f.Confidence)
			}
			if ev.Type != events.EvPIIHit {
				t.Fatalf("event type = %q, want %q", ev.Type, events.EvPIIHit)
			}
			if ev.Severity.Order() < tc.wantSev.Order() {
				t.Fatalf("severity = %s, want >= %s", ev.Severity, tc.wantSev)
			}
			if !ev.HasAction(events.ActAlert) || !ev.HasAction(events.ActDeny) || !ev.HasAction(events.ActMask) {
				t.Fatalf("actions wrong: %v", ev.Actions)
			}
		})
	}
}

func TestInvalidLuhnNotFlagged(t *testing.T) {
	d := mustDetector(t, config.PIIConfig{})
	ev := &events.Event{Type: events.EvQueryAudit, Severity: events.SevInfo,
		SQL: "SELECT * FROM customers WHERE card = '4111111111111112'"}
	if fs := d.Evaluate(ev); len(fs) != 0 {
		t.Fatalf("Luhn-invalid card must yield no findings, got %+v", fs)
	}
	if ev.Type != events.EvQueryAudit {
		t.Fatalf("event must stay %q, got %q", events.EvQueryAudit, ev.Type)
	}
}

func TestAlertOnlyConfig(t *testing.T) {
	d := mustDetector(t, config.PIIConfig{AlertOnly: true})
	ev := &events.Event{Type: events.EvQueryAudit, Severity: events.SevInfo,
		SQL: "SELECT * FROM customers WHERE card = '4111111111111111'"}
	fs := d.Evaluate(ev)
	if len(fs) == 0 {
		t.Fatal("expected findings")
	}
	if !ev.HasAction(events.ActAlert) {
		t.Fatal("alert action missing")
	}
	if ev.HasAction(events.ActDeny) || ev.HasAction(events.ActMask) {
		t.Fatalf("alert_only must not add enforcement actions: %v", ev.Actions)
	}
}

// TestEntropyGate verifies the secret-like pattern accepts high-entropy
// payloads and rejects low-entropy fillers at the configured threshold.
func TestEntropyGate(t *testing.T) {
	d := mustDetector(t, config.PIIConfig{EntropyThreshold: 4.0})
	high := "SELECT * FROM cfg WHERE aws_secret_key = 'qK7zX2vB9mN4pR8tY3wE6uJ1hF5dG0aLcS+oI=xZ'"
	if fs := d.InspectText(high); indexOfKind(fs, "pii.aws_secret") < 0 {
		t.Fatalf("high-entropy secret not flagged: %+v", fs)
	}
	low := "SELECT * FROM cfg WHERE aws_secret_key = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA'"
	if fs := d.InspectText(low); indexOfKind(fs, "pii.aws_secret") >= 0 {
		t.Fatalf("low-entropy filler must not be flagged: %+v", fs)
	}
}

func TestInspectTextOffsets(t *testing.T) {
	d := mustDetector(t, config.PIIConfig{})
	text := "note: 4111111111111111 end"
	fs := d.InspectText(text)
	if len(fs) == 0 {
		t.Fatal("no findings")
	}
	f := fs[0]
	if f.Start < 0 || f.End > len(text) || f.Start >= f.End {
		t.Fatalf("offsets out of bounds: %+v", f)
	}
	if got := text[f.Start:f.End]; got != "4111111111111111" {
		t.Fatalf("span text = %q, want the card number", got)
	}
	if !strings.Contains(f.Snippet, "1111") {
		t.Fatalf("snippet %q not masked keep-last-4", f.Snippet)
	}
}

func TestResultSampleScanned(t *testing.T) {
	d := mustDetector(t, config.PIIConfig{})
	ev := &events.Event{Type: events.EvQueryAudit, Severity: events.SevInfo,
		SQL:  "SELECT note FROM t",
		Meta: map[string]string{"result_sample": "4111111111111111"}}
	fs := d.Evaluate(ev)
	if indexOfKind(fs, "pii.credit_card") < 0 {
		t.Fatalf("result_sample not scanned: %+v", fs)
	}
}

func TestPatternSelection(t *testing.T) {
	if _, err := New(config.PIIConfig{Patterns: []string{"no_such_pattern"}}, nil); err == nil {
		t.Fatal("unknown pattern list must return an error")
	}
	d := mustDetector(t, config.PIIConfig{
		Patterns:         []string{"credit_card", "ssn_us"},
		DisabledPatterns: []string{"ssn_us"},
	})
	fs := d.InspectText("ssn 123-45-6789 card 4111111111111111")
	if indexOfKind(fs, "pii.credit_card") < 0 {
		t.Fatalf("credit_card missing: %+v", fs)
	}
	if indexOfKind(fs, "pii.ssn_us") >= 0 {
		t.Fatalf("disabled pattern still active: %+v", fs)
	}
}

func TestMaskModes(t *testing.T) {
	if got := Mask("4111111111111111", MaskKeepLast4); got != "************1111" {
		t.Fatalf("MaskKeepLast4 = %q", got)
	}
	if got := Mask("abc", MaskKeepLast4); got != "***" {
		t.Fatalf("MaskKeepLast4 short value = %q", got)
	}
	if got := Mask("secret", MaskFull); got != "******" {
		t.Fatalf("MaskFull = %q", got)
	}
	if got := Mask("secret", MaskHash); len(got) != 8 {
		t.Fatalf("MaskHash = %q, want 8 hex chars", got)
	}
	if got := Mask("secret", MaskMode(99)); got != "******" {
		t.Fatalf("unknown mode must fail closed, got %q", got)
	}
}

func TestRedactor(t *testing.T) {
	d := mustDetector(t, config.PIIConfig{})
	text := "a 4111111111111111 b"
	red := d.Redactor()(text)
	if strings.Contains(red, "4111111111111111") {
		t.Fatalf("raw card survived redaction: %q", red)
	}
	if !strings.Contains(red, "1111") {
		t.Fatalf("redacted text lost masked snippet: %q", red)
	}
	if same := d.Redactor()("SELECT 1"); same != "SELECT 1" {
		t.Fatalf("clean text must be returned unchanged, got %q", same)
	}
}
