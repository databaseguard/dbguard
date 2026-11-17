// Package anomaly - per-client behavioural profiles.
//
// A clientProfile carries the sliding windows and counters the detector
// needs per (client IP, database user) pair. ProfileStore bounds memory at
// maxProfiles entries and serialises updates so the multi-goroutine
// pipeline can never interleave counter read-modify-write cycles.
package anomaly

import (
	"sync"
	"time"
)

// maxProfiles caps tracked clients; when the store is full it is reset
// wholesale (eviction is arbitrary by design: profiles rebuild within one
// detection window).
const maxProfiles = 4096

// clientProfile is the behavioural state of one client key.
type clientProfile struct {
	queryTimes *slidingWindow // weighted query samples
	connOpens  *slidingWindow // weighted connection-open samples

	authFailures  int       // consecutive failed auths (reset after alert)
	adminConns    int       // concurrent admin sessions (open/close tracked)
	lastRateAlert time.Time // min-gap governor for rate alerts
	firstSeen     time.Time
	lastSeen      time.Time
}

// ProfileStore maps client keys onto profiles under one mutex.
type ProfileStore struct {
	mu sync.Mutex
	m  map[string]*clientProfile
}

// newProfileStore returns an empty bounded store.
func newProfileStore() *ProfileStore {
	return &ProfileStore{m: make(map[string]*clientProfile, 64)}
}

// Get returns the profile for key, creating (and, when full, evicting) as
// needed. The returned pointer is shared: mutate it via Update or while
// holding the store lock.
func (s *ProfileStore) Get(key string) *clientProfile {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.get(key)
}

// Update runs fn under the store lock with the (possibly freshly created)
// profile for key. It is the only sanctioned way to read-modify-write
// profile counters from the detector.
func (s *ProfileStore) Update(key string, fn func(p *clientProfile)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.get(key))
}

// ForEach calls fn for every profile while holding the store lock. fn must
// not call back into the store (deadlock); it may mutate the profile and
// its windows (which carry their own locks).
func (s *ProfileStore) ForEach(fn func(p *clientProfile)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, p := range s.m {
		fn(p)
	}
}

// Len returns the number of tracked profiles.
func (s *ProfileStore) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}

// get is the lock-held fast path of Get/Update.
func (s *ProfileStore) get(key string) *clientProfile {
	if p, ok := s.m[key]; ok {
		return p
	}
	if len(s.m) >= maxProfiles {
		// wholesale reset: cheaper than LRU bookkeeping at pipeline rates
		s.m = make(map[string]*clientProfile, 64)
	}
	p := &clientProfile{
		queryTimes: newSlidingWindow(queryWindowCapacity),
		connOpens:  newSlidingWindow(connWindowCapacity),
	}
	s.m[key] = p
	return p
}

// touch records activity timestamps (helper shared by detector paths).
func (p *clientProfile) touch(now time.Time) {
	if p.firstSeen.IsZero() {
		p.firstSeen = now
	}
	p.lastSeen = now
}
