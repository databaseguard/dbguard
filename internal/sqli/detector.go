// Package sqli - the firewall detector: combines signature hits into a
// single confidence score, applies the sensitivity multiplier and enforces
// the configured threshold on the event (deny + alert, reclassification and
// severity bump).
package sqli

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/detect"
	"github.com/databaseguard/dbguard/internal/events"
)

// compile-time interface check.
var _ detect.Detector = (*Detector)(nil)

// Sensitivity multipliers: how aggressively raw scores cross the threshold.
const (
	sensLow    = 0.8
	sensMedium = 1.0
	sensHigh   = 1.25
)

// DefaultConfidenceThreshold is used when the config leaves it unset.
const DefaultConfidenceThreshold = 0.72

// Detector scores SQL statements against the signature catalogue. It is
// immutable after construction and safe for concurrent use.
type Detector struct {
	threshold  float64 // deny above this adjusted score
	sensMult   float64 // sensitivity multiplier applied to raw scores
	maxSQLLen  int     // statements are truncated before analysis
	log        *slog.Logger
	signatures []*Signature
}

// New builds the SQL injection firewall from cfg. Sensitivity maps
// low/medium/high onto score multipliers 0.8/1.0/1.25 (unknown values fall
// back to medium). New never fails for config content; the error return
// keeps the constructor signature stable for the daemon wiring.
func New(cfg config.SQLiConfig, log *slog.Logger) (*Detector, error) {
	if log == nil {
		log = slog.Default()
	}
	var mult float64
	switch strings.ToLower(cfg.Sensitivity) {
	case "low":
		mult = sensLow
	case "high":
		mult = sensHigh
	default: // medium or unset (config validation rejects other values)
		mult = sensMedium
	}
	threshold := cfg.ConfidenceThreshold
	if threshold <= 0 || threshold > 1 {
		threshold = DefaultConfidenceThreshold
	}
	return &Detector{
		threshold:  threshold,
		sensMult:   mult,
		maxSQLLen:  cfg.MaxSQLLen,
		log:        log,
		signatures: allSignatures(),
	}, nil
}

// Name implements detect.Detector.
func (d *Detector) Name() string { return "sqli" }

// Analyze scores an SQL statement without engine filtering (all signatures
// evaluate) and returns the combined confidence score plus one finding per
// matched signature. It is the entry point for the CLI test-sqli command.
func (d *Detector) Analyze(sql string) (float64, []events.Finding) {
	score, findings, _ := d.analyze(sql, "")
	return score, findings
}

// Evaluate implements detect.Detector. When the adjusted score reaches the
// threshold the event is reclassified as EvSQLi, its severity bumped to the
// worst matched signature, deny+alert actions added and an aggregate
// finding ("sqli.aggregate") carrying the final confidence appended.
func (d *Detector) Evaluate(ev *events.Event) []events.Finding {
	if ev == nil || ev.SQL == "" {
		return nil
	}
	score, findings, worst := d.analyze(ev.SQL, ev.Engine)
	if len(findings) == 0 {
		return nil
	}
	if score >= d.threshold {
		ev.Type = events.EvSQLi
		if worst.Order() > ev.Severity.Order() {
			ev.Severity = worst
		}
		ev.AddAction(events.ActDeny)
		ev.AddAction(events.ActAlert)
		findings = append(findings, events.Finding{
			Kind: "sqli.aggregate",
			Detail: fmt.Sprintf("sql injection score %.2f >= threshold %.2f (sensitivity x%.2f)",
				score, d.threshold, d.sensMult),
			Confidence: score,
		})
		if d.log != nil {
			d.log.Info("sqli: injection denied",
				"score", score, "threshold", d.threshold, "engine", ev.Engine)
		}
	}
	return findings
}

// analyze runs the signature set over sql. engine ("" = unknown) filters
// engine-specific signatures; the score is the noisy-OR of matched
// weights times the sensitivity multiplier, capped at 1.0.
func (d *Detector) analyze(sql string, engine string) (float64, []events.Finding, events.Severity) {
	if sql == "" {
		return 0, nil, events.SevInfo
	}
	if d.maxSQLLen > 0 && len(sql) > d.maxSQLLen {
		sql = sql[:d.maxSQLLen]
	}
	c := newScanCtx(sql)

	score := 0.0
	worst := events.SevInfo
	var findings []events.Finding
	for _, sig := range d.signatures {
		if len(sig.Engines) > 0 && engine != "" && !containsFold(sig.Engines, engine) {
			continue
		}
		if !sig.Test(c) {
			continue
		}
		findings = append(findings, events.Finding{
			Kind:       sig.ID,
			Detail:     sig.Name,
			Confidence: sig.Weight,
		})
		score = 1 - (1-score)*(1-sig.Weight) // noisy-OR combination
		if sig.Severity.Order() > worst.Order() {
			worst = sig.Severity
		}
	}
	if d.sensMult != 1.0 && score > 0 {
		score *= d.sensMult
		if score > 1 {
			score = 1
		}
	}
	return score, findings, worst
}

// containsFold reports whether list contains v case-insensitively.
func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}
