// jsonl.go implements the shipped audit.Store backend: rotating JSON Lines
// files named dbguard-audit-<UTC-timestamp>.jsonl.
//
// The format is deliberately SIEM-friendly - Filebeat, Vector or Fluent Bit
// can tail the directory and ship records without transformation, and
// jq/grep cover ad-hoc forensics. Each line is one complete Event JSON
// object followed by '\n'.
//
// Redaction contract: when cfg.RedactPII is set, upstream stages (PII
// detector masking, pipeline) are responsible for masking before Append -
// the store stays a dumb, faithful writer so audit records remain verifiable.
package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

const (
	queueSize  = 4096 // Append backlog before Append reports "queue full"
	filePrefix = "dbguard-audit-"
	fileExt    = ".jsonl"
	timeLayout = "20060102-150405"
)

// JSONLStore is a rotating JSONL audit store. Append is queued and written
// by a single background goroutine (ordered, no interleaving); Query scans
// segment files oldest-first; Close flushes and releases.
type JSONLStore struct {
	cfg config.AuditConfig
	log *slog.Logger
	dir string

	ch chan *events.Event

	mu      sync.RWMutex // guards f/bw/written/closed
	f       *os.File
	bw      *bufio.Writer
	written int64
	closed  bool

	wg        sync.WaitGroup
	closeOnce sync.Once
}

// NewJSONLStore creates the audit directory and the first segment file and
// starts the single writer goroutine.
func NewJSONLStore(cfg config.AuditConfig, log *slog.Logger) (*JSONLStore, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.Dir == "" {
		return nil, fmt.Errorf("audit: dir is required")
	}
	if err := os.MkdirAll(cfg.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("audit: mkdir %s: %w", cfg.Dir, err)
	}
	s := &JSONLStore{
		cfg: cfg,
		log: log,
		dir: cfg.Dir,
		ch:  make(chan *events.Event, queueSize),
	}
	if err := s.openNewLocked(); err != nil {
		return nil, err
	}
	s.log.Info("audit: jsonl store open", "dir", s.dir,
		"max_size_mb", cfg.MaxSizeMB, "max_files", cfg.MaxFiles)
	s.wg.Add(1)
	go s.writer()
	return s, nil
}

// Append queues one event for durable persistence. It never blocks: when
// the queue is full an error is returned (the pipeline counts/logs it) so
// the hot path stays unblocked.
func (s *JSONLStore) Append(_ context.Context, ev *events.Event) error {
	if ev == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return fmt.Errorf("audit: store is closed")
	}
	select {
	case s.ch <- ev:
		return nil
	default:
		return fmt.Errorf("audit: queue full (%d entries), event dropped", queueSize)
	}
}

// Query scans segment files in chronological order (the UTC timestamp in
// the file name makes lexicographic order chronological) and returns
// matching events. Default limit 500, hard cap 10000. Malformed lines are
// skipped so a torn tail write cannot break the query.
func (s *JSONLStore) Query(_ context.Context, f Filter) ([]*events.Event, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 500
	}
	if limit > 10000 {
		limit = 10000
	}
	var out []*events.Event
	for _, path := range s.files() {
		if len(out) >= limit {
			break
		}
		fh, err := os.Open(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue // rotated away mid-query
			}
			return nil, fmt.Errorf("audit: open %s: %w", path, err)
		}
		dec := json.NewDecoder(bufio.NewReader(fh))
		for dec.More() {
			var ev events.Event
			if err := dec.Decode(&ev); err != nil {
				s.log.Debug("audit: skipping malformed line", "file", path, "err", err)
				break
			}
			if f.Match(&ev) {
				out = append(out, &ev)
				if len(out) >= limit {
					break
				}
			}
		}
		_ = fh.Close()
	}
	return out, nil
}

// RotateNow closes the current segment and opens a fresh one, then prunes
// to MaxFiles. Exposed for ops tooling and tests.
func (s *JSONLStore) RotateNow() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rotateLocked()
}

// Close flushes pending events, closes the segment file and stops the
// writer goroutine. Idempotent; Append after Close returns an error.
func (s *JSONLStore) Close() error {
	s.closeOnce.Do(func() {
		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			return
		}
		s.closed = true
		s.mu.Unlock()
		close(s.ch) // safe: Append checks closed under RLock before sending
		s.wg.Wait() // writer drains the queue, flushes and exits
	})
	return nil
}

// writer is the single background goroutine: it serialises writes, flushes
// on the configured interval and rotates when the segment grows past
// MaxSizeMB.
func (s *JSONLStore) writer() {
	defer s.wg.Done()
	interval := 2 * time.Second
	if s.cfg.FlushIntervalSec > 0 {
		interval = time.Duration(s.cfg.FlushIntervalSec) * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case ev, ok := <-s.ch:
			if !ok {
				s.mu.Lock()
				s.flushLocked()
				s.closeFileLocked()
				s.mu.Unlock()
				return
			}
			s.write(ev)
		case <-t.C:
			s.mu.Lock()
			s.flushLocked()
			s.mu.Unlock()
		}
	}
}

// write marshals and appends one event, rotating when needed.
func (s *JSONLStore) write(ev *events.Event) {
	b, err := json.Marshal(ev)
	if err != nil {
		s.log.Warn("audit: marshal event", "id", ev.ID, "err", err)
		return
	}
	b = append(b, '\n')
	s.mu.Lock()
	defer s.mu.Unlock()
	// Note: we intentionally do NOT bail out on s.closed here. Close() sets
	// s.closed=true and then closes the channel; the writer goroutine then
	// drains the remaining queued events through this path before closing
	// the file. Guarding on s.closed would silently drop every event still
	// queued at Close time. The file handle (s.bw) is the real guard: it is
	// nil only after closeFileLocked, which the writer calls last.
	if s.bw == nil {
		return
	}
	n, err := s.bw.Write(b)
	s.written += int64(n)
	if err != nil {
		s.log.Warn("audit: write failed", "err", err)
		return
	}
	if max := s.maxBytes(); max > 0 && s.written >= max {
		if err := s.rotateLocked(); err != nil {
			s.log.Warn("audit: rotation failed", "err", err)
		}
	}
}

// maxBytes returns the rotation threshold (0 = size rotation disabled).
func (s *JSONLStore) maxBytes() int64 {
	if s.cfg.MaxSizeMB <= 0 {
		return 0
	}
	return int64(s.cfg.MaxSizeMB) << 20
}

// rotateLocked flushes, closes the current segment, opens a new one and
// prunes old segments. Caller holds s.mu for writing.
func (s *JSONLStore) rotateLocked() error {
	s.flushLocked()
	s.closeFileLocked()
	if err := s.openNewLocked(); err != nil {
		return err
	}
	s.pruneLocked()
	return nil
}

// openNewLocked creates a uniquely named segment file for the current UTC
// second (second-resolution collisions get a -NN counter suffix).
func (s *JSONLStore) openNewLocked() error {
	base := time.Now().UTC().Format(timeLayout)
	var path string
	// Always carry a zero-padded counter (-00, -01, ...). Within the same UTC
	// second this disambiguates rapid rotations, and because every name has
	// the same shape its lexicographic order equals its creation order - which
	// files()/Query() rely on to return events oldest-first.
	for i := 0; ; i++ {
		name := fmt.Sprintf("%s%s-%02d%s", filePrefix, base, i, fileExt)
		p := filepath.Join(s.dir, name)
		if _, err := os.Stat(p); os.IsNotExist(err) {
			path = p
			break
		}
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", path, err)
	}
	s.f, s.bw, s.written = f, bufio.NewWriter(f), 0
	return nil
}

// flushLocked pushes buffered bytes to the OS and fsyncs.
func (s *JSONLStore) flushLocked() {
	if s.bw != nil {
		if err := s.bw.Flush(); err != nil {
			s.log.Warn("audit: flush failed", "err", err)
		}
	}
	if s.f != nil {
		if err := s.f.Sync(); err != nil {
			s.log.Debug("audit: sync failed", "err", err)
		}
	}
}

// closeFileLocked closes the current segment (if any).
func (s *JSONLStore) closeFileLocked() {
	if s.f == nil {
		return
	}
	_ = s.f.Close()
	s.f, s.bw, s.written = nil, nil, 0
}

// pruneLocked enforces MaxFiles by mtime, deleting the oldest segments.
// MaxFiles <= 0 disables pruning.
func (s *JSONLStore) pruneLocked() {
	if s.cfg.MaxFiles <= 0 {
		return
	}
	matches := s.files()
	if len(matches) <= s.cfg.MaxFiles {
		return
	}
	type dated struct {
		path string
		mod  time.Time
	}
	var segs []dated
	for _, p := range matches {
		fi, err := os.Stat(p)
		if err != nil {
			continue
		}
		segs = append(segs, dated{path: p, mod: fi.ModTime()})
	}
	sort.Slice(segs, func(i, j int) bool { return segs[i].mod.Before(segs[j].mod) })
	for i := 0; i < len(segs)-s.cfg.MaxFiles; i++ {
		if err := os.Remove(segs[i].path); err != nil {
			s.log.Warn("audit: prune failed", "file", segs[i].path, "err", err)
		} else {
			s.log.Debug("audit: pruned segment", "file", segs[i].path)
		}
	}
}

// files lists segment paths sorted oldest-first.
func (s *JSONLStore) files() []string {
	matches, _ := filepath.Glob(filepath.Join(s.dir, filePrefix+"*"+fileExt))
	sort.Strings(matches)
	return matches
}

// ensure the store contract is satisfied (compile-time).
var _ Store = (*JSONLStore)(nil)
