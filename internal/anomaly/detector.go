// Package anomaly - the detector: evaluates events against per-client
// sliding windows and the configured thresholds, emitting findings and
// enforcement suggestions (rate limit / deny) on the event itself.
package anomaly

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/detect"
	"github.com/databaseguard/dbguard/internal/events"
)

// compile-time interface checks: the anomaly module is both a Detector and
// a Runner (background window sweeps).
var (
	_ detect.Detector = (*Detector)(nil)
	_ detect.Runner   = (*Detector)(nil)
)

// Operational defaults mirroring config.AnomalyConfig; used when New
// receives zero-valued fields (tests/CLI).
const (
	defaultWindowSec     = 60
	defaultQueryRate     = 80 // queries per second per client
	defaultConnSpike     = 40 // new connections per window
	defaultAdminMax      = 3  // concurrent admin sessions
	defaultFailedAuthMax = 10 // consecutive auth failures
	rateAlertGap         = 30 * time.Second
	sweepInterval        = 30 * time.Second
)

// adminUsers are the built-in superuser names tracked for the concurrent
// admin session limit.
var adminUsers = map[string]bool{
	"postgres": true, "root": true, "sa": true, "admin": true, "dba": true,
}

// Detector implements connection/behavioural anomaly detection. Evaluate is
// safe for concurrent use (all profile mutation is store-serialised).
type Detector struct {
	window      time.Duration
	queryRate   float64
	connSpike   int
	adminMax    int
	authFailMax int
	profiles    *ProfileStore
	log         *slog.Logger
}

// New builds the anomaly detector from cfg, filling unset thresholds with
// the operational defaults. The error return keeps the constructor signature
// stable for daemon wiring; New never fails on config content.
func New(cfg config.AnomalyConfig, log *slog.Logger) (*Detector, error) {
	if log == nil {
		log = slog.Default()
	}
	windowSec := cfg.WindowSec
	if windowSec <= 0 {
		windowSec = defaultWindowSec
	}
	queryRate := cfg.QueryRateThreshold
	if queryRate <= 0 {
		queryRate = defaultQueryRate
	}
	connSpike := cfg.ConnSpikeThreshold
	if connSpike <= 0 {
		connSpike = defaultConnSpike
	}
	adminMax := cfg.AdminConcurrentMax
	if adminMax <= 0 {
		adminMax = defaultAdminMax
	}
	authFailMax := cfg.FailedAuthThreshold
	if authFailMax <= 0 {
		authFailMax = defaultFailedAuthMax
	}
	return &Detector{
		window:      time.Duration(windowSec) * time.Second,
		queryRate:   queryRate,
		connSpike:   connSpike,
		adminMax:    adminMax,
		authFailMax: authFailMax,
		profiles:    newProfileStore(),
		log:         log,
	}, nil
}

// Name implements detect.Detector.
func (d *Detector) Name() string { return "anomaly" }

// Evaluate dispatches by event type. Findings are returned and, where the
// spec requires, the event is reclassified, severity-bumped and given
// enforcement actions.
func (d *Detector) Evaluate(ev *events.Event) []events.Finding {
	if ev == nil {
		return nil
	}
	now := ev.Time
	if now.IsZero() {
		now = time.Now()
	}
	switch ev.Type {
	case events.EvQueryAudit:
		return d.onQuery(ev, now)
	case events.EvConnOpen:
		return d.onConnOpen(ev, now)
	case events.EvAuthAnomaly:
		return d.onAuthFail(ev, now)
	case events.EvConnClose:
		d.onConnClose(ev)
		return nil
	default:
		return nil
	}
}

// onQuery tracks query rate per client and fires at most once per
// rateAlertGap per profile to avoid alert storms.
func (d *Detector) onQuery(ev *events.Event, now time.Time) []events.Finding {
	key := clientKey(ev)
	var findings []events.Finding
	d.profiles.Update(key, func(p *clientProfile) {
		p.queryTimes.Add(now, 1)
		p.touch(now)
		rate := p.queryTimes.Rate(d.window, now)
		if rate > d.queryRate && now.Sub(p.lastRateAlert) >= rateAlertGap {
			p.lastRateAlert = now
			findings = append(findings, events.Finding{
				Kind: "anomaly.query_rate",
				Detail: fmt.Sprintf("query rate %.1f/s exceeds %.1f/s for %s over %s",
					rate, d.queryRate, key, d.window),
				Confidence: 0.9,
			})
		}
	})
	if len(findings) > 0 {
		ev.Type = events.EvConnAnomaly
		bumpSeverity(ev, events.SevHigh)
		ev.AddAction(events.ActRateLimit)
		ev.AddAction(events.ActAlert)
	}
	return findings
}

// onConnOpen tracks connection bursts and concurrent admin sessions.
func (d *Detector) onConnOpen(ev *events.Event, now time.Time) []events.Finding {
	key := clientKey(ev)
	var findings []events.Finding
	worst := events.SevInfo
	d.profiles.Update(key, func(p *clientProfile) {
		p.connOpens.Add(now, 1)
		p.touch(now)

		count := p.connOpens.Count(d.window, now)
		if count > float64(d.connSpike) {
			sev := events.SevMedium
			if count > float64(2*d.connSpike) {
				sev = events.SevHigh
			}
			if sev.Order() > worst.Order() {
				worst = sev
			}
			findings = append(findings, events.Finding{
				Kind: "anomaly.conn_spike",
				Detail: fmt.Sprintf("%d new connections within %s for %s (threshold %d)",
					int(count), d.window, key, d.connSpike),
				Confidence: 0.85,
			})
		}
		if adminUsers[ev.User] {
			p.adminConns++
			if p.adminConns > d.adminMax {
				if events.SevHigh.Order() > worst.Order() {
					worst = events.SevHigh
				}
				findings = append(findings, events.Finding{
					Kind: "anomaly.admin_concurrent",
					Detail: fmt.Sprintf("%d concurrent admin sessions for %s (max %d)",
						p.adminConns, key, d.adminMax),
					Confidence: 0.9,
				})
			}
		}
	})
	if len(findings) > 0 {
		ev.Type = events.EvConnAnomaly
		bumpSeverity(ev, worst)
		ev.AddAction(events.ActAlert)
	}
	return findings
}

// onAuthFail counts consecutive authentication failures; when the threshold
// is reached it alerts once and resets the counter to avoid alert storms.
func (d *Detector) onAuthFail(ev *events.Event, now time.Time) []events.Finding {
	var findings []events.Finding
	d.profiles.Update(clientKey(ev), func(p *clientProfile) {
		p.touch(now)
		p.authFailures++
		if p.authFailures >= d.authFailMax {
			p.authFailures = 0
			findings = append(findings, events.Finding{
				Kind: "anomaly.auth_bruteforce",
				Detail: fmt.Sprintf("%d consecutive auth failures for %s (threshold %d)",
					d.authFailMax, clientKey(ev), d.authFailMax),
				Confidence: 0.95,
			})
		}
	})
	if len(findings) > 0 {
		bumpSeverity(ev, events.SevHigh)
		ev.AddAction(events.ActDeny)
		ev.AddAction(events.ActAlert)
	}
	return findings
}

// onConnClose decrements the concurrent admin session counter (floored at
// zero so duplicated closes cannot corrupt tracking).
func (d *Detector) onConnClose(ev *events.Event) {
	d.profiles.Update(clientKey(ev), func(p *clientProfile) {
		if p.adminConns > 0 {
			p.adminConns--
		}
	})
}

// Run implements detect.Runner: a 30s sweep prunes both windows so idle
// clients stop contributing to rates and counters.
func (d *Detector) Run(ctx context.Context) error {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			d.profiles.ForEach(func(p *clientProfile) {
				p.queryTimes.Prune(2*d.window, now)
				p.connOpens.Prune(2*d.window, now)
			})
		}
	}
}

// Close implements detect.Runner; the detector keeps no background
// resources beyond the caller-owned context, so Close is a no-op.
func (d *Detector) Close() error { return nil }

// clientKey is the per-client profile key: source IP plus database user.
func clientKey(ev *events.Event) string {
	return ev.ClientIP + "/" + ev.User
}

// bumpSeverity raises ev.Severity to at least sev.
func bumpSeverity(ev *events.Event, sev events.Severity) {
	if sev.Order() > ev.Severity.Order() {
		ev.Severity = sev
	}
}
