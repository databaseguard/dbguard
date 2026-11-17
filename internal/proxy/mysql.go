package proxy

// MySQL / MariaDB synchronous inline enforcement.
//
// The MySQL client/server protocol frames every message as a 4-byte header
// (3-byte little-endian payload length + 1-byte sequence id) followed by the
// payload. The very first client packet is the HandshakeResponse, which carries
// the username and (optionally) the default schema. Subsequent client packets
// begin with a COM_* command byte; COM_QUERY (0x03) and COM_STMT_PREPARE (0x16)
// carry SQL text, and COM_INIT_DB (0x02) switches the active database.
//
// On a denied statement the proxy does NOT forward the packet; it replies to
// the client with a protocol-correct ERR packet (sequence = client seq + 1) and
// drops the frame, so the database never sees the query. The session stays
// usable and the next statement is evaluated again.

import (
	"context"
	"encoding/binary"
	"io"
	"time"

	"github.com/databaseguard/dbguard/internal/policy"
	"github.com/databaseguard/dbguard/internal/proto"
)

// handleMySQL proxies one MySQL/MariaDB client connection with inline policy
// enforcement on the client→server direction.
func (p *Proxy) handleMySQL(ctx context.Context, client, up io.ReadWriteCloser, clientIP string) {
	s := &mySession{p: p, client: client, up: up, clientIP: clientIP, sawHandshake: false}

	// server→client: relay, but strip CLIENT_SSL from the initial handshake so
	// the client stays in plaintext and the proxy can inspect COM_QUERY.
	done := make(chan struct{})
	go func() { relayServerToClient(client, up); close(done) }()

	// client→server: framed, policy-enforced.
	s.pump(ctx)

	up.Close()
	client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
	}
}

// mySession carries per-connection state for the client→server direction.
type mySession struct {
	p        *Proxy
	client   io.ReadWriteCloser
	up       io.ReadWriteCloser
	clientIP string

	buf          []byte
	sawHandshake bool // first client packet (HandshakeResponse) seen yet?
	user         string
	database     string
	queryAttrs   bool // client negotiated CLIENT_QUERY_ATTRIBUTES (MySQL 8.0.23+)
}

// relayServerToClient copies server→client bytes, but rewrites the server's
// initial handshake packet to clear CLIENT_SSL so the client does not upgrade to
// TLS (which would make COM_QUERY invisible to the proxy). After the first
// packet it is a plain relay.
func relayServerToClient(client, up io.ReadWriteCloser) {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(up, hdr); err != nil {
		return
	}
	plen := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	payload := make([]byte, plen)
	if _, err := io.ReadFull(up, payload); err != nil {
		return
	}
	proto.ClearServerSSLCap(payload) // in place; no-op if not a handshake
	client.Write(hdr)
	client.Write(payload)
	io.Copy(client, up)
}

// pump reads client bytes, frames them, enforces policy, forwards allowed bytes.
func (s *mySession) pump(ctx context.Context) {
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

// feed appends new bytes and processes every complete MySQL packet buffered.
func (s *mySession) feed(data []byte) error {
	s.buf = append(s.buf, data...)
	for {
		if len(s.buf) < 4 {
			return nil
		}
		plen := int(s.buf[0]) | int(s.buf[1])<<8 | int(s.buf[2])<<16
		seq := s.buf[3]
		total := 4 + plen
		if plen > 1<<24 { // 16MB sanity cap; desync - drop one byte
			s.buf = s.buf[1:]
			continue
		}
		if len(s.buf) < total {
			return nil
		}
		frame := s.buf[:total]
		payload := frame[4:]

		if !s.sawHandshake {
			// First client packet is the HandshakeResponse: learn user/schema.
			if user, db, ok := proto.ParseHandshakeResponse(payload); ok {
				s.user = user
				s.database = db
			}
			// Remember whether the client negotiated query attributes, so SQL
			// extraction can skip that header on COM_QUERY.
			const clientQueryAttributes = 1 << 27
			if proto.ClientCapabilities(payload)&clientQueryAttributes != 0 {
				s.queryAttrs = true
			}
			s.sawHandshake = true
			if _, err := s.up.Write(frame); err != nil {
				return err
			}
			s.buf = s.buf[total:]
			continue
		}

		pkt := proto.MySQLPacket{Seq: seq, Payload: payload}

		// Track active database on COM_INIT_DB (USE <db>).
		if db, ok := proto.ParseComInitDB(pkt); ok {
			s.database = db
		}

		// COM_QUERY / COM_STMT_PREPARE carry SQL we enforce.
		if sql, ok := proto.ExtractSQLMySQLCaps(pkt, s.queryAttrs); ok {
			if s.enforce(sql, seq) {
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
// protocol-correct ERR packet). It returns false to allow.
func (s *mySession) enforce(sql string, seq byte) bool {
	cid, clabels := s.p.identity(s.clientIP)
	dec := s.p.eng.Evaluate(&policy.Context{
		Engine:         "mysql",
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
		"engine", "mysql", "user", s.user, "db", s.database, "client", s.clientIP,
		"rule", rule, "sql", truncate(sql, 120))
	if s.p.onDeny != nil {
		s.p.onDeny(sql, s.user, s.database, s.clientIP, rule)
	}
	msg := "dbguard: query blocked by policy"
	if rule != "" {
		msg += " (rule " + rule + ")"
	}
	// ERR packet sequence id must be the client's seq + 1.
	s.client.Write(mysqlErrPacket(seq+1, 1045, "28000", msg))
	return true
}

// mysqlErrPacket builds a MySQL ERR packet.
//
// Body: 0xFF, u16 error code (LE), '#', 5-byte SQLSTATE, human message.
// Header: 3-byte LE payload length + 1-byte sequence id.
func mysqlErrPacket(seq byte, code uint16, sqlState, message string) []byte {
	body := make([]byte, 0, 4+len(sqlState)+len(message))
	body = append(body, 0xFF)
	body = append(body, byte(code), byte(code>>8))
	body = append(body, '#')
	st := sqlState
	if len(st) != 5 {
		st = "HY000"
	}
	body = append(body, []byte(st)...)
	body = append(body, []byte(message)...)

	out := make([]byte, 4+len(body))
	out[0] = byte(len(body))
	out[1] = byte(len(body) >> 8)
	out[2] = byte(len(body) >> 16)
	out[3] = seq
	copy(out[4:], body)
	return out
}

var _ = binary.LittleEndian
