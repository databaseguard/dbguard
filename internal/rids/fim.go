// File-integrity monitoring (FIM) for the RIDS module: Baseline is the
// on-disk-serializable path→sha256 state, Scanner walks the configured
// directory trees (never following symlinks) and produces baselines and
// diffs. Hashing is capped at DefaultMaxFileSize per file so a runaway log
// or a core dump cannot stall the sweep.
package rids

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

const (
	// DefaultMaxFileSize caps hashed files at 64 MiB.
	DefaultMaxFileSize int64 = 64 << 20
	// hashBufSize bounds the copy buffer used while hashing.
	hashBufSize = 1 << 20
)

// Baseline is the FIM state: absolute file path → sha256 hex digest.
type Baseline map[string]string

// Save persists the baseline as indented JSON at path (mode 0600). The
// write is atomic: data lands in "<path>.tmp" and is renamed into place,
// so readers never observe a torn file.
func (b Baseline) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return fmt.Errorf("rids: encode baseline: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return fmt.Errorf("rids: write baseline %s: %w", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rids: publish baseline %s: %w", path, err)
	}
	return nil
}

// LoadBaseline reads a baseline previously written by Save.
func LoadBaseline(path string) (Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rids: read baseline %s: %w", path, err)
	}
	b := Baseline{}
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("rids: parse baseline %s: %w", path, err)
	}
	return b, nil
}

// Scanner hashes a set of directory trees with a per-file size cap.
// It is stateless and safe for concurrent use.
type Scanner struct {
	dirs    []string
	maxSize int64
}

// NewScanner returns a scanner over dirs. maxSize <= 0 selects
// DefaultMaxFileSize (64 MiB); empty dir entries are dropped.
func NewScanner(dirs []string, maxSize int64) *Scanner {
	if maxSize <= 0 {
		maxSize = DefaultMaxFileSize
	}
	clean := make([]string, 0, len(dirs))
	for _, d := range dirs {
		if d != "" {
			clean = append(clean, d)
		}
	}
	return &Scanner{dirs: clean, maxSize: maxSize}
}

// Baseline walks every configured directory and hashes regular files.
// Symlinks are never followed; sockets, devices and FIFOs are ignored;
// files larger than the size cap are skipped; unreadable or vanished
// entries are skipped silently (permission holes must not wedge FIM).
// The returned error, if any, is the first non-skip-worthy walk/hash
// error encountered - the baseline itself is still usable.
func (s *Scanner) Baseline() (Baseline, error) {
	b := make(Baseline, 1024)
	var firstErr error
	note := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for _, dir := range s.dirs {
		walkErr := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				note(err)
				return nil
			}
			if !d.Type().IsRegular() {
				return nil // dirs, symlinks, sockets, devices, FIFOs
			}
			info, err := d.Info()
			if err != nil {
				return nil // raced away mid-walk
			}
			if info.Size() > s.maxSize {
				return nil
			}
			sum, err := hashFile(p)
			if err != nil {
				if errors.Is(err, fs.ErrPermission) || errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				note(err)
				return nil
			}
			b[p] = sum
			return nil
		})
		if walkErr != nil {
			note(walkErr)
		}
	}
	return b, firstErr
}

// Diff re-hashes the trees and compares against old. It returns the
// added / removed / changed paths (each sorted for deterministic output)
// and the next baseline to feed into a subsequent Diff. A nil old baseline
// reports every file as added.
func (s *Scanner) Diff(old Baseline) (added, removed, changed []string, next Baseline, err error) {
	next, err = s.Baseline()
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("rids: fim diff: %w", err)
	}
	if old == nil {
		old = Baseline{}
	}
	for p, sum := range next {
		oldSum, ok := old[p]
		switch {
		case !ok:
			added = append(added, p)
		case oldSum != sum:
			changed = append(changed, p)
		}
	}
	for p := range old {
		if _, ok := next[p]; !ok {
			removed = append(removed, p)
		}
	}
	sort.Strings(added)
	sort.Strings(changed)
	sort.Strings(removed)
	return added, removed, changed, next, nil
}

// hashFile computes the sha256 hex digest of the file at path. The size
// cap is enforced by the caller (info.Size() before open); if the file
// grows between stat and read the hash covers what was read, which is the
// documented TOCTOU trade-off for a non-blocking monitor.
func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	buf := make([]byte, hashBufSize)
	if _, err := io.CopyBuffer(h, f, buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
