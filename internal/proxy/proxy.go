// Package proxy implements a synchronous, protocol-aware database proxy that
// enforces dbguard policy INLINE - a denied query is rejected before it ever
// reaches the database, so (unlike the asynchronous uprobe path) no rows are
// ever returned for a blocked statement, regardless of how fast the query is.
//
// The proxy sits in front of the DB port: clients connect to the proxy, the
// proxy dials the real database, and it relays bytes in both directions. On the
// client→server direction it frames the PostgreSQL wire protocol, extracts each
// Query ('Q') / Parse ('P') statement, runs it through the policy engine, and:
//
//   - allow  → forwards the message untouched
//   - deny   → does NOT forward; sends a PostgreSQL ErrorResponse back to the
//     client and (for simple query) a ReadyForQuery, so the session
//     stays usable and the next statement is evaluated again.
//
// This is the "hard, synchronous, pre-result blocking" path: the database never
// sees a denied query. It complements the uprobe auditing (which still observes
// direct/local connections that bypass the proxy).
package proxy

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/databaseguard/dbguard/internal/policy"
	"github.com/databaseguard/dbguard/internal/proto"
)

// Config controls one proxy listener.
type Config struct {
	Listen   string // address the proxy listens on, e.g. 127.0.0.1:6432
	Upstream string // real database address, e.g. 127.0.0.1:5432
	Engine   string // "postgres", "mysql", or "mariadb"
}

// Evaluator is the policy decision function the proxy calls per statement.
// It matches policy.Engine.Evaluate without importing a concrete type, so the
// proxy is easy to test.
type Evaluator interface {
	Evaluate(*policy.Context) policy.Decision
}

// Proxy is a single listening proxy instance.
type Proxy struct {
	cfg    Config
	eng    Evaluator
	log    *slog.Logger
	ln     net.Listener
	wg     sync.WaitGroup
	onDeny func(sql, user, db, clientIP, rule string) // optional audit hook
	// identityFor resolves a client IP to its Cilium security-identity id and
	// labels, so identity-scoped policy rules ("only the api-server identity may
	// query") are enforced inline at the proxy. nil = no identity resolution.
	identityFor func(ip string) (id string, labels []string, ok bool)
}

// New creates a proxy. onDeny may be nil.
func New(cfg Config, eng Evaluator, log *slog.Logger,
	onDeny func(sql, user, db, clientIP, rule string)) *Proxy {
	if log == nil {
		log = slog.Default()
	}
	return &Proxy{cfg: cfg, eng: eng, log: log, onDeny: onDeny}
}

// SetIdentityResolver installs the Cilium identity resolver used to gate
// identity-scoped rules at the proxy. Safe to call once before Start.
func (p *Proxy) SetIdentityResolver(f func(ip string) (string, []string, bool)) {
	p.identityFor = f
}

// identity resolves (id, labels) for a client IP, or ("", nil) when no resolver
// is configured or the IP is unknown.
func (p *Proxy) identity(ip string) (string, []string) {
	if p.identityFor == nil || ip == "" {
		return "", nil
	}
	id, labels, ok := p.identityFor(ip)
	if !ok {
		return "", nil
	}
	return id, labels
}

// Start begins listening and serving until ctx is cancelled.
func (p *Proxy) Start(ctx context.Context) error {
	lc := net.ListenConfig{}
	ln, err := lc.Listen(ctx, "tcp", p.cfg.Listen)
	if err != nil {
		return err
	}
	p.ln = ln
	p.log.Info("proxy: listening (synchronous inline enforcement)",
		"listen", p.cfg.Listen, "upstream", p.cfg.Upstream, "engine", p.cfg.Engine)

	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				p.wg.Wait()
				return nil
			}
			continue
		}
		p.wg.Add(1)
		go func() { defer p.wg.Done(); p.handle(ctx, conn) }()
	}
}

// handle proxies one client connection.
func (p *Proxy) handle(ctx context.Context, client net.Conn) {
	defer client.Close()
	clientIP, _, _ := net.SplitHostPort(client.RemoteAddr().String())

	up, err := net.DialTimeout("tcp", p.cfg.Upstream, 5*time.Second)
	if err != nil {
		p.log.Warn("proxy: upstream dial failed", "upstream", p.cfg.Upstream, "err", err)
		return
	}
	defer up.Close()

	// MySQL / MariaDB speak a different wire protocol; dispatch to the
	// MySQL-aware session handler. Everything else is treated as PostgreSQL.
	if p.cfg.Engine == "mysql" || p.cfg.Engine == "mariadb" {
		p.handleMySQL(ctx, client, up, clientIP)
		return
	}

	sess := &pgSession{
		p: p, client: client, up: up, clientIP: clientIP,
	}
	// server→client: straight relay (we don't rewrite results).
	done := make(chan struct{})
	go func() { io.Copy(client, up); close(done) }()
	// client→server: framed, policy-enforced.
	sess.pump(ctx)
	// ensure the relay goroutine ends
	up.Close()
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
}

// pgSession carries per-connection state for the client→server direction.
type pgSession struct {
	p        *Proxy
	client   net.Conn
	up       net.Conn
	clientIP string

	startupDone bool
	user        string
	database    string
	buf         []byte
}

// pump reads client bytes, frames them, enforces policy, forwards allowed bytes.
func (s *pgSession) pump(ctx context.Context) {
	rd := make([]byte, 32*1024)
	for {
		if ctx.Err() != nil {
			return
		}
		n, err := s.client.Read(rd)
		if n > 0 {
			if ferr := s.feed(rd[:n]); ferr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// feed appends new bytes and processes every complete frame currently buffered.
func (s *pgSession) feed(data []byte) error {
	s.buf = append(s.buf, data...)
	for {
		if !s.startupDone {
			// StartupMessage: int32 len (includes itself), then body.
			if len(s.buf) < 8 {
				return nil
			}
			total := int(binary.BigEndian.Uint32(s.buf[0:4]))
			code := binary.BigEndian.Uint32(s.buf[4:8])
			// SSLRequest (80877103) / GSSENCRequest (80877104) are 8-byte framed
			// requests whose length field is exactly 8 - which otherwise looks
			// like a valid (tiny) startup, so they MUST be detected by the magic
			// code, not the length (the old `total < 8` test missed them, which
			// made the proxy forward the SSLRequest upstream and hang the client
			// on psql's default sslmode=prefer). The proxy must see plaintext to
			// enforce policy, so it declines encryption by replying 'N' directly
			// to the client (never forwarded upstream); the client then sends a
			// normal plaintext startup, which we inspect. (For production TLS,
			// terminate TLS at the proxy; declining is the safe default for a
			// local enforcement proxy.)
			if total == 8 && (code == 80877103 || code == 80877104) {
				if _, err := s.client.Write([]byte{'N'}); err != nil {
					return err
				}
				s.buf = s.buf[8:]
				continue
			}
			if total < 8 || total > 1<<20 {
				// Not a 3.0 startup / cancel request: switch to passthrough framing.
				s.startupDone = true
				continue
			}
			if len(s.buf) < total {
				return nil
			}
			params := proto.ParseStartup(s.buf[:total])
			s.user = params["user"]
			s.database = params["database"]
			if s.database == "" {
				s.database = s.user
			}
			// forward the startup untouched
			if _, err := s.up.Write(s.buf[:total]); err != nil {
				return err
			}
			s.buf = s.buf[total:]
			s.startupDone = true
			continue
		}

		// Regular message: byte type + int32 length (includes itself).
		if len(s.buf) < 5 {
			return nil
		}
		mtype := s.buf[0]
		length := int(binary.BigEndian.Uint32(s.buf[1:5]))
		if length < 4 || length > 1<<22 {
			// desync - forward one byte and resync (defensive)
			if _, err := s.up.Write(s.buf[:1]); err != nil {
				return err
			}
			s.buf = s.buf[1:]
			continue
		}
		total := 1 + length
		if len(s.buf) < total {
			return nil
		}
		frame := s.buf[:total]
		payload := frame[5:]

		// Only Query/Parse carry SQL we enforce; everything else is forwarded.
		if mtype == proto.PGMsgQuery || mtype == proto.PGMsgParse {
			sql, ok := proto.ExtractSQLPostgres(proto.Message{Type: mtype, Payload: payload})
			if ok && s.enforce(sql, mtype) {
				// DENIED: do not forward. Reject inline and drop this frame.
				s.buf = s.buf[total:]
				continue
			}
		}
		// ALLOWED (or non-SQL): forward the frame verbatim.
		if _, err := s.up.Write(frame); err != nil {
			return err
		}
		s.buf = s.buf[total:]
	}
}

// enforce returns true if the statement is DENIED (and sends the client a
// protocol-correct rejection). It returns false to allow.
func (s *pgSession) enforce(sql string, mtype byte) bool {
	cid, clabels := s.p.identity(s.clientIP)
	dec := s.p.eng.Evaluate(&policy.Context{
		Engine:         "postgres",
		User:           s.user,
		Database:       s.database,
		ClientIP:       s.clientIP,
		SQL:            sql,
		Tables:         proto.ExtractTables(sql),
		Columns:        proto.ExtractColumns(sql),
		CiliumIdentity: cid,
		CiliumLabels:   clabels,
		Now:            time.Now(),
	})
	if dec.Allowed {
		return false
	}
	rule := ""
	if len(dec.RuleIDs) > 0 {
		rule = dec.RuleIDs[0]
	}
	s.p.log.Info("proxy: query DENIED inline (database never saw it)",
		"user", s.user, "db", s.database, "client", s.clientIP, "rule", rule,
		"sql", truncate(sql, 120))
	if s.p.onDeny != nil {
		s.p.onDeny(sql, s.user, s.database, s.clientIP, rule)
	}
	// Send a PostgreSQL ErrorResponse, then ReadyForQuery for a simple Query so
	// the session can continue. For extended-protocol Parse, the client will
	// Sync and we send ReadyForQuery on that boundary too.
	msg := "dbguard: query blocked by policy"
	if rule != "" {
		msg += " (rule " + rule + ")"
	}
	s.client.Write(pgErrorResponse(msg))
	if mtype == proto.PGMsgQuery {
		s.client.Write(pgReadyForQuery())
	}
	return true
}

// pgErrorResponse builds a PostgreSQL ErrorResponse ('E') packet.
// Fields: S=severity, V=severity(non-localized), C=SQLSTATE, M=message.
func pgErrorResponse(message string) []byte {
	var body []byte
	add := func(code byte, val string) {
		body = append(body, code)
		body = append(body, []byte(val)...)
		body = append(body, 0)
	}
	add('S', "ERROR")
	add('V', "ERROR")
	add('C', "42501") // insufficient_privilege
	add('M', message)
	body = append(body, 0) // terminator

	out := make([]byte, 1+4+len(body))
	out[0] = 'E'
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(body)))
	copy(out[5:], body)
	return out
}

// pgReadyForQuery builds a ReadyForQuery ('Z') packet (status 'I' = idle).
func pgReadyForQuery() []byte {
	return []byte{'Z', 0, 0, 0, 5, 'I'}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
