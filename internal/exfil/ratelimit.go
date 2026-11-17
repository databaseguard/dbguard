// Package exfil is DBGuard's bulk-dump breaker: it watches kernel-fed
// byte-count events per session, quarantines offenders that blow through
// the configured window/rate budget and flags dump-shaped SELECT *
// statements on the query path. ratelimit.go provides the token-bucket
// limiter used to annotate (and locally throttle) exfil sessions.
package exfil

import (
	"sync"
	"time"
)

// tokenBucket is a classic token-bucket byte limiter: tokens refill at rate
// bytes per second up to burst, and Take consumes from the balance. All
// operations are goroutine-safe and time is always supplied by the caller,
// which keeps the bucket deterministic under test.
type tokenBucket struct {
	mu     sync.Mutex
	rate   float64   // refill bytes per second
	burst  float64   // maximum balance
	tokens float64   // current balance
	last   time.Time // last refill timestamp
}

// newTokenBucket starts a full bucket (burst tokens) at the current time.
func newTokenBucket(bytesPerSec float64, burst uint64) *tokenBucket {
	if bytesPerSec < 0 {
		bytesPerSec = 0
	}
	if burst == 0 {
		burst = 1
	}
	// last is left as the zero Time on purpose: the bucket's clock is driven
	// entirely by the caller-supplied timestamps (keeping it deterministic
	// under test), so it adopts the time of the first Take/Balance call rather
	// than the wall clock, which may be unrelated to the caller's time base.
	return &tokenBucket{
		rate:   bytesPerSec,
		burst:  float64(burst),
		tokens: float64(burst),
	}
}

// Take consumes up to n tokens at time now. It returns the number of tokens
// granted and whether the full request was satisfied; shortfalls grant the
// remaining balance (floor) so partial progress is still metered.
func (b *tokenBucket) Take(n uint64, now time.Time) (granted uint64, ok bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.After(b.last) {
		b.refillLocked(now)
	}
	if n == 0 {
		return 0, true
	}
	if float64(n) <= b.tokens {
		b.tokens -= float64(n)
		return n, true
	}
	granted = uint64(b.tokens) // floor of the remaining balance
	b.tokens -= float64(granted)
	return granted, false
}

// TakeFloat is Take for fractional callers (tests, metrics); same refill
// and short-fall semantics with a float budget.
func (b *tokenBucket) Balance(now time.Time) float64 {
	b.mu.Lock()
	defer b.mu.Unlock()
	if now.After(b.last) {
		b.refillLocked(now)
	}
	return b.tokens
}

// refillLocked credits elapsed*rate tokens, capped at burst, and advances
// the refill clock. Caller holds b.mu.
func (b *tokenBucket) refillLocked(now time.Time) {
	// First use: adopt the caller's clock without crediting any tokens.
	if b.last.IsZero() {
		b.last = now
		return
	}
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 && b.rate > 0 {
		b.tokens += elapsed * b.rate
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
	}
	b.last = now
}
