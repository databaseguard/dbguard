// Package anomaly detects connection-level and behavioural anomalies:
// query-rate bursts, connection spikes, authentication brute force and
// concurrent administrative logins, tracked per client over sliding time
// windows.
//
// window.go holds the thread-safe sliding window primitive every counter
// builds on.
package anomaly

import (
	"sync"
	"time"
)

// defaultWindowCapacity bounds per-profile window memory: 256 query samples
// and 128 connection samples cover any realistic detection window.
const (
	queryWindowCapacity = 256
	connWindowCapacity  = 128
)

// slidingWindow is a fixed-capacity ring of (time, weight) samples.
// Overwrites replace the oldest sample; empty slots carry a zero time.Time
// and never contribute. All operations are goroutine-safe.
type slidingWindow struct {
	mu   sync.Mutex
	ts   []time.Time
	w    []float64
	next int // next slot to overwrite
}

// newSlidingWindow returns a window holding up to capacity samples.
func newSlidingWindow(capacity int) *slidingWindow {
	if capacity < 1 {
		capacity = 1
	}
	return &slidingWindow{
		ts: make([]time.Time, capacity),
		w:  make([]float64, capacity),
	}
}

// Add records one weighted sample at now.
func (s *slidingWindow) Add(now time.Time, weight float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ts[s.next] = now
	s.w[s.next] = weight
	s.next++
	if s.next == len(s.ts) {
		s.next = 0
	}
}

// Rate returns the weighted sum of samples newer than now-since, divided by
// the window length in seconds (events per second). A non-positive since
// yields 0.
func (s *slidingWindow) Rate(since time.Duration, now time.Time) float64 {
	if since <= 0 {
		return 0
	}
	return s.sumSince(now.Add(-since)) / since.Seconds()
}

// Count returns the weighted sum of samples inside the window
// (Rate x seconds, without the floating point round-trip).
func (s *slidingWindow) Count(since time.Duration, now time.Time) float64 {
	if since <= 0 {
		return 0
	}
	return s.sumSince(now.Add(-since))
}

// Prune clears samples older than now-olderThan so idle windows stop
// contributing and memory is reusable.
func (s *slidingWindow) Prune(olderThan time.Duration, now time.Time) {
	if olderThan <= 0 {
		return
	}
	cut := now.Add(-olderThan)
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.ts {
		if !s.ts[i].IsZero() && s.ts[i].Before(cut) {
			s.ts[i] = time.Time{}
			s.w[i] = 0
		}
	}
}

// sumSince sums the weights of samples strictly after cut. Caller must not
// hold s.mu.
func (s *slidingWindow) sumSince(cut time.Time) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sum float64
	for i := range s.ts {
		if !s.ts[i].IsZero() && s.ts[i].After(cut) {
			sum += s.w[i]
		}
	}
	return sum
}
