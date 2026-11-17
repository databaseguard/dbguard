// Package alert - file.go implements the local JSONL file sink with
// size-based rotation. It is the default sink for standalone deployments
// and the source of truth consumed by SIEM forwarders.
package alert

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

const (
	// fileMaxBytes is the rotation threshold when SinkConfig has no
	// explicit size knob: 100 MiB per active file.
	fileMaxBytes = 100 << 20
	// fileKeep is the number of rotated files (.1 .. .5) kept on disk.
	fileKeep = 5
	// fileBufSize is the bufio buffer used between flushes.
	fileBufSize = 64 << 10
)

// FileSink appends one JSON object per line to SinkConfig.File.
type FileSink struct {
	path string
	max  int64
	keep int
	log  *slog.Logger

	mu      sync.Mutex
	f       *os.File
	w       *bufio.Writer
	written int64
}

// NewFile validates the config, creates the parent directory and opens (or
// reopens) the alert log in append mode.
func NewFile(cfg config.SinkConfig, log *slog.Logger) (*FileSink, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.File == "" {
		return nil, fmt.Errorf("alert: file sink requires file path")
	}
	if err := os.MkdirAll(filepath.Dir(cfg.File), 0o755); err != nil {
		return nil, fmt.Errorf("alert: file sink mkdir %s: %w", filepath.Dir(cfg.File), err)
	}
	f, err := os.OpenFile(cfg.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("alert: file sink open %s: %w", cfg.File, err)
	}
	var size int64
	if st, err := f.Stat(); err == nil {
		size = st.Size()
	}
	return &FileSink{
		path:    cfg.File,
		max:     fileMaxBytes,
		keep:    fileKeep,
		log:     log,
		f:       f,
		w:       bufio.NewWriterSize(f, fileBufSize),
		written: size,
	}, nil
}

// Name implements Sink.
func (s *FileSink) Name() string { return "file" }

// Send appends one JSON line. The buffer is flushed after every alert so a
// crash never loses notifications; Close flushes as a final safety net.
func (s *FileSink) Send(_ context.Context, ev *events.Event) error {
	line, err := json.Marshal(renderEvent(ev))
	if err != nil {
		return fmt.Errorf("alert: file marshal: %w", err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.written+int64(len(line)) > s.max {
		if err := s.rotateLocked(); err != nil {
			return err
		}
	}
	if _, err := s.w.Write(line); err != nil {
		return fmt.Errorf("alert: file write %s: %w", s.path, err)
	}
	s.written += int64(len(line))
	if err := s.w.Flush(); err != nil {
		return fmt.Errorf("alert: file flush %s: %w", s.path, err)
	}
	return nil
}

// rotateLocked shifts .1..(.keep-1) up by one and moves the current file to
// .1; caller holds s.mu. Individual rename failures are logged but do not
// abort rotation - losing one old generation beats losing new alerts.
func (s *FileSink) rotateLocked() error {
	if err := s.w.Flush(); err != nil {
		return fmt.Errorf("alert: file flush before rotate: %w", err)
	}
	if err := s.f.Close(); err != nil {
		return fmt.Errorf("alert: file close before rotate: %w", err)
	}
	for i := s.keep - 1; i >= 1; i-- {
		if err := os.Rename(s.path+"."+strconv.Itoa(i), s.path+"."+strconv.Itoa(i+1)); err != nil && !os.IsNotExist(err) {
			s.log.Warn("alert: rotation shift failed", "file", s.path, "gen", i, "error", err)
		}
	}
	if err := os.Rename(s.path, s.path+".1"); err != nil && !os.IsNotExist(err) {
		s.log.Warn("alert: rotation rename failed", "file", s.path, "error", err)
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		s.f = nil // Closed() then reports cleanly instead of double-closing
		s.w = nil
		return fmt.Errorf("alert: file reopen %s: %w", s.path, err)
	}
	s.f = f
	s.w = bufio.NewWriterSize(f, fileBufSize)
	s.written = 0
	s.log.Info("alert: rotated file sink", "file", s.path, "keep", s.keep)
	return nil
}

// Close flushes the buffer and closes the underlying file.
func (s *FileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return nil
	}
	err := s.w.Flush()
	if cerr := s.f.Close(); err == nil {
		err = cerr
	}
	s.f = nil
	s.w = nil
	if err != nil {
		return fmt.Errorf("alert: file close %s: %w", s.path, err)
	}
	return nil
}
