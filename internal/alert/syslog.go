// Package alert - syslog.go implements the RFC5424 syslog sink over UDP.
// Each alert becomes one framed message:
//
//	<PRI>1 <RFC3339 timestamp> <hostname> dbguard - - - <BOM><json payload>
//
// PRI = facility*8 + severity, with the facility defaulting to local0 (16)
// and event severities mapped onto the syslog scale (critical=2 .. info=6).
package alert

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

// rfc5424BOM marks the MSG as UTF-8 as required by RFC 5424.
const rfc5424BOM = "\uFEFF"

// defaultSyslogPort is the IANA-assigned syslog port.
const defaultSyslogPort = 514

// SyslogSink emits one RFC5424 UDP datagram per alert. UDP was chosen so a
// dead collector can never back the pipeline up; delivery is best-effort by
// design (the router counts write failures).
type SyslogSink struct {
	mu       sync.Mutex
	addr     string
	facility int
	hostname string
	conn     net.Conn
	log      *slog.Logger
}

// syslogFacilities maps RFC 5424 facility keywords onto numeric codes.
var syslogFacilities = map[string]int{
	"kern": 0, "user": 1, "mail": 2, "daemon": 3, "auth": 4, "syslog": 5,
	"lpr": 6, "news": 7, "uucp": 8, "cron": 9, "authpriv": 10, "ftp": 11,
	"local0": 16, "local1": 17, "local2": 18, "local3": 19,
	"local4": 20, "local5": 21, "local6": 22, "local7": 23,
}

// parseFacility resolves a facility name to its code, defaulting to local0.
func parseFacility(name string) int {
	if code, ok := syslogFacilities[strings.ToLower(strings.TrimSpace(name))]; ok {
		return code
	}
	return syslogFacilities["local0"]
}

// syslogSeverity maps DBGuard severities onto the RFC 5424 severity scale
// (0 emerg .. 7 debug).
func syslogSeverity(sev events.Severity) int {
	switch sev {
	case events.SevCritical:
		return 2 // crit
	case events.SevHigh:
		return 3 // err
	case events.SevMedium:
		return 4 // warning
	case events.SevLow:
		return 5 // notice
	default:
		return 6 // info
	}
}

// NewSyslog validates the sink config (host required) and prepares the
// connection state; the UDP socket is created lazily on first send.
func NewSyslog(cfg config.SinkConfig, log *slog.Logger) (*SyslogSink, error) {
	if log == nil {
		log = slog.Default()
	}
	if cfg.Host == "" {
		return nil, fmt.Errorf("alert: syslog sink requires host")
	}
	port := cfg.Port
	if port <= 0 {
		port = defaultSyslogPort
	}
	hostname, err := os.Hostname()
	if err != nil || hostname == "" {
		hostname = "unknown"
	}
	return &SyslogSink{
		addr:     net.JoinHostPort(cfg.Host, strconv.Itoa(port)),
		facility: parseFacility(cfg.Facility),
		hostname: hostname,
		log:      log,
	}, nil
}

// Name implements Sink.
func (s *SyslogSink) Name() string { return "syslog" }

// Send renders one RFC5424 datagram and writes it, re-dialing once on write
// failure. A dial failure (typically DNS) is returned so the router can
// count it.
func (s *SyslogSink) Send(ctx context.Context, ev *events.Event) error {
	payload, err := json.Marshal(renderEvent(ev))
	if err != nil {
		return fmt.Errorf("alert: syslog marshal: %w", err)
	}
	pri := s.facility*8 + syslogSeverity(ev.Severity)
	line := fmt.Sprintf("<%d>1 %s %s dbguard - - - %s%s",
		pri, time.Now().UTC().Format(time.RFC3339), s.hostname, rfc5424BOM, payload)

	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.write([]byte(line)); err != nil {
		// One reconnect attempt; stale UDP sockets occasionally surface
		// after network changes even though UDP itself is connectionless.
		s.closeLocked()
		if err := s.write([]byte(line)); err != nil {
			return fmt.Errorf("alert: syslog %s: %w", s.addr, err)
		}
	}
	return nil
}

// write dials (if needed) and writes one datagram; caller holds s.mu.
func (s *SyslogSink) write(b []byte) error {
	if s.conn == nil {
		d := net.Dialer{Timeout: 3 * time.Second}
		conn, err := d.DialContext(context.Background(), "udp", s.addr)
		if err != nil {
			return err // caller counts the failure
		}
		s.conn = conn
	}
	_, err := s.conn.Write(b)
	return err
}

// closeLocked drops the socket; caller holds s.mu.
func (s *SyslogSink) closeLocked() {
	if s.conn != nil {
		_ = s.conn.Close()
		s.conn = nil
	}
}
