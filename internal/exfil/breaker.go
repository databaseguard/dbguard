// Package exfil - the breaker detector: per-session byte accounting fed by
// the kernel (meta "bytes_window"), quarantine windows with optional
// connection reset, bulk-SELECT flagging on the query path and a background
// sweep that expires dead sessions.
package exfil

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"sync"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/detect"
	"github.com/databaseguard/dbguard/internal/events"
)

// compile-time interface checks: the breaker is a Detector and a Runner.
var (
	_ detect.Detector = (*Breaker)(nil)
	_ detect.Runner   = (*Breaker)(nil)
)

// bulkSelectRe matches dump-shaped statements: any SELECT * regardless of
// spacing/case. The kernel's kflag_bulk_select meta takes precedence when
// present.
var bulkSelectRe = regexp.MustCompile(`(?i)select\s+\*`)

// Defaults mirroring config.ExfilConfig; used for zero-valued fields.
const (
	defaultQuarantineSec = 30
	defaultBurstBytes    = 8 << 20           // 8 MiB per window burst
	defaultRateBytesSec  = 200 * 1024 * 1024 // 200 MB/s sustained ceiling
	sweepInterval        = 5 * time.Second
)

// session is the breaker state for one socket-cookie session.
type session struct {
	bytesTotal       uint64
	winBytes         uint64
	winStart         time.Time
	quarantinedUntil time.Time
	bulkFlag         bool
	lastActive       time.Time
	bucket           *tokenBucket
}

// Breaker implements the exfil detector and background sweeper. Evaluate is
// safe for concurrent use.
type Breaker struct {
	quarantine   time.Duration
	window       time.Duration
	burstBytes   uint64
	rateBytes    float64
	resetEnabled bool
	sessions     map[uint64]*session
	mu           sync.Mutex
	log          *slog.Logger
	nowFn        func() time.Time // injectable clock (tests)
}

// New builds the bulk-dump breaker from cfg. The error return keeps the
// constructor signature stable for daemon wiring; New never fails on
// config content.
func New(cfg config.ExfilConfig, log *slog.Logger) (*Breaker, error) {
	if log == nil {
		log = slog.Default()
	}
	quarantineSec := cfg.QuarantineSec
	if quarantineSec <= 0 {
		quarantineSec = defaultQuarantineSec
	}
	windowMS := cfg.WindowMS
	if windowMS <= 0 {
		windowMS = 100
	}
	burst := cfg.MaxBytesPerWindow
	if burst == 0 {
		burst = defaultBurstBytes
	}
	rate := float64(cfg.MaxRateKbps) * 1024 // Kbps -> bytes/sec
	if rate <= 0 {
		rate = defaultRateBytesSec
	}
	return &Breaker{
		quarantine:   time.Duration(quarantineSec) * time.Second,
		window:       time.Duration(windowMS) * time.Millisecond,
		burstBytes:   burst,
		rateBytes:    rate,
		resetEnabled: cfg.ResetEnabled,
		sessions:     make(map[uint64]*session),
		log:          log,
		nowFn:        time.Now,
	}, nil
}

// Name implements detect.Detector.
func (b *Breaker) Name() string { return "exfil" }

// Evaluate dispatches by event type: kernel byte-window events quarantine,
// bulk SELECT statements are flagged, connection teardown drops state.
func (b *Breaker) Evaluate(ev *events.Event) []events.Finding {
	if ev == nil {
		return nil
	}
	switch ev.Type {
	case events.EvExfil:
		return b.onKernelExfil(ev)
	case events.EvQueryAudit:
		return b.onQuery(ev)
	case events.EvConnClose:
		b.mu.Lock()
		delete(b.sessions, ev.SessionID)
		b.mu.Unlock()
		return nil
	default:
		return nil
	}
}

// onKernelExfil handles a kernel-fed byte-window report: accumulate, arm
// the quarantine window, annotate throttling and request enforcement.
func (b *Breaker) onKernelExfil(ev *events.Event) []events.Finding {
	bytes := parseBytes(ev.MetaGet("bytes_window"))
	now := b.now()

	// Defense in depth against a bad byte count: a window at or above 4 GiB is
	// the signature of a signed/unsigned underflow in kernel accounting (a
	// negative tcp_sendmsg errno cast to u64 ≈ 2^32). No single 100 ms window
	// legitimately moves 4 GiB, so treat such a report as noise and do NOT
	// quarantine on it. This keeps a stale/older BPF object from falsely
	// quarantining clients (including loopback).
	const implausibleWindow = uint64(4) << 30 // 4 GiB
	if bytes >= implausibleWindow {
		if b.log != nil {
			b.log.Debug("exfil: ignoring implausible byte window (kernel underflow guard)",
				"bytes_window", bytes)
		}
		return nil
	}

	b.mu.Lock()
	s := b.sessionLocked(ev.SessionID, now)
	s.bytesTotal += bytes
	total := s.bytesTotal
	if s.winStart.IsZero() || now.Sub(s.winStart) >= b.window {
		s.winStart = now
		s.winBytes = bytes
	} else {
		s.winBytes += bytes
	}
	s.quarantinedUntil = now.Add(b.quarantine)
	granted, ok := s.bucket.Take(bytes, now)
	b.mu.Unlock()

	ev.MetaSet("exfil_granted", strconv.FormatUint(granted, 10))
	if !ok {
		ev.MetaSet("exfil_throttled", "1")
	}
	ev.AddAction(events.ActQuarantine)
	if b.resetEnabled {
		ev.AddAction(events.ActReset)
	}
	bumpSeverity(ev, events.SevCritical)

	if b.log != nil {
		b.log.Info("exfil: burst quarantined",
			"session", ev.SessionID, "bytes_window", bytes, "granted", granted)
	}
	return []events.Finding{{
		Kind: "exfil.burst",
		Detail: fmt.Sprintf("kernel reported %d bytes in window (session total %d); quarantined for %s",
			bytes, total, b.quarantine),
		Confidence: 1.0,
	}}
}

// onQuery flags dump-shaped SELECT * statements (kernel pre-filter flag or
// user-space regex) and tracks the bulkFlag per session.
func (b *Breaker) onQuery(ev *events.Event) []events.Finding {
	if ev.MetaGet("kflag_bulk_select") != "1" && !bulkSelectRe.MatchString(ev.SQL) {
		return nil
	}
	now := b.now()
	b.mu.Lock()
	s := b.sessionLocked(ev.SessionID, now)
	repeat := s.bulkFlag
	s.bulkFlag = true
	b.mu.Unlock()

	detail := "unbounded SELECT * moves whole tables; cap with LIMIT or column projection"
	if repeat {
		detail = "repeated bulk SELECT * from the same session: " + detail
	}
	bumpSeverity(ev, events.SevHigh)
	ev.AddAction(events.ActAlert)
	return []events.Finding{{
		Kind:       "exfil.bulk_query",
		Detail:     detail,
		Confidence: 0.7,
	}}
}

// Quarantined reports whether the session is inside its quarantine window.
func (b *Breaker) Quarantined(session uint64) bool {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	s := b.sessions[session]
	return s != nil && now.Before(s.quarantinedUntil)
}

// Run implements detect.Runner: a 5s sweep drops sessions whose quarantine
// has expired and that have been idle for a minute.
func (b *Breaker) Run(ctx context.Context) error {
	ticker := time.NewTicker(sweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			b.sweep(now)
		}
	}
}

// Close implements detect.Runner; no background resources are owned.
func (b *Breaker) Close() error { return nil }

// sweep expires idle, un-quarantined sessions.
func (b *Breaker) sweep(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for id, s := range b.sessions {
		if now.After(s.quarantinedUntil) && now.Sub(s.lastActive) > time.Minute {
			delete(b.sessions, id)
		}
	}
}

// sessionLocked returns the session for id, creating it (with its token
// bucket) on first sight. Caller holds b.mu.
func (b *Breaker) sessionLocked(id uint64, now time.Time) *session {
	s := b.sessions[id]
	if s == nil {
		s = &session{
			winStart: now,
			bucket:   newTokenBucket(b.rateBytes, b.burstBytes),
		}
		b.sessions[id] = s
	}
	s.lastActive = now
	return s
}

// now returns the (injectable) current time.
func (b *Breaker) now() time.Time {
	if b.nowFn != nil {
		return b.nowFn()
	}
	return time.Now()
}

// parseBytes parses the kernel's decimal byte count, defaulting to 0.
func parseBytes(s string) uint64 {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0
	}
	return n
}

// bumpSeverity raises ev.Severity to at least sev.
func bumpSeverity(ev *events.Event, sev events.Severity) {
	if sev.Order() > ev.Severity.Order() {
		ev.Severity = sev
	}
}
