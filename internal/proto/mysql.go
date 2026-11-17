package proto

// MySQL Client/Server protocol parsing.
//
// Reference: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic.html
//
// Every packet: int24 payload_length (LE), byte sequence_id, payload.
// Client commands of interest: COM_QUERY (0x03), COM_STMT_PREPARE (0x16),
// COM_STMT_EXECUTE (0x17), COM_QUIT (0x01), COM_PING (0x0e).
// Handshake Response 41 carries user/database during connection setup.

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// MySQL command bytes (client -> server).
const (
	MySQLComQuit        byte = 0x01
	MySQLComInitDB      byte = 0x02
	MySQLComQuery       byte = 0x03
	MySQLComStmtPrepare byte = 0x16
	MySQLComStmtExecute byte = 0x17
	MySQLComStmtClose   byte = 0x19
	MySQLComPing        byte = 0x0e
)

// capability flag used when parsing HandshakeResponse41.
const clientConnectWithDB = 0x00000008

// MySQLParser incrementally decodes a MySQL connection byte stream.
type MySQLParser struct {
	buf       []byte
	handshake bool // expect HandshakeResponse first
	sawQuery  bool
}

// NewMySQLParser creates a parser for a single connection stream.
func NewMySQLParser() *MySQLParser {
	return &MySQLParser{handshake: true}
}

// Feed appends bytes and returns all complete packets.
func (p *MySQLParser) Feed(data []byte) []MySQLPacket {
	p.buf = append(p.buf, data...)
	var out []MySQLPacket
	for {
		if len(p.buf) < 4 {
			return out
		}
		length := int(u24(p.buf[0:3]))
		if length > 1<<22 { // 4MB sanity cap
			p.buf = p.buf[1:]
			continue
		}
		if len(p.buf) < 4+length {
			return out
		}
		seq := p.buf[3]
		payload := bytes.Clone(p.buf[4 : 4+length])
		p.buf = p.buf[4+length:]

		if p.handshake {
			if user, db, ok := ParseHandshakeResponse(payload); ok {
				_ = user
				_ = db
				p.handshake = false
			}
			// SSLRequest packets (short) also clear the handshake phase
			if len(payload) >= 32 {
				p.handshake = false
			}
			continue
		}
		if len(payload) > 0 && payload[0] == MySQLComQuery {
			p.sawQuery = true
		}
		out = append(out, MySQLPacket{Seq: seq, Payload: payload})
	}
}

// SawQuery reports whether any COM_QUERY was decoded.
func (p *MySQLParser) SawQuery() bool { return p.sawQuery }

// IsClientCommand reports whether payload starts with a known COM_* byte.
func IsClientCommand(payload []byte) bool {
	if len(payload) == 0 {
		return false
	}
	switch payload[0] {
	case MySQLComQuit, MySQLComInitDB, MySQLComQuery, MySQLComStmtPrepare,
		MySQLComStmtExecute, MySQLComStmtClose, MySQLComPing:
		return true
	}
	return false
}

// CLIENT_QUERY_ATTRIBUTES (1<<27): MySQL 8.0.23+ clients (incl. the mysql CLI)
// prepend a query-attributes header to COM_QUERY, before the SQL text.
const clientQueryAttributes = 1 << 27

// CLIENT_SSL (1<<11): advertised by the server in its initial handshake; when a
// client sees it, it may send an SSLRequest and upgrade to TLS before the
// HandshakeResponse. The inline proxy clears this bit so the client stays in
// plaintext and the proxy can inspect COM_QUERY.
const clientSSL = 1 << 11

// lenencInt decodes a MySQL length-encoded integer. ok is false if truncated.
func lenencInt(b []byte) (val uint64, n int, ok bool) {
	if len(b) == 0 {
		return 0, 0, false
	}
	switch b[0] {
	case 0xfb: // NULL
		return 0, 1, true
	case 0xfc:
		if len(b) < 3 {
			return 0, 0, false
		}
		return uint64(b[1]) | uint64(b[2])<<8, 3, true
	case 0xfd:
		if len(b) < 4 {
			return 0, 0, false
		}
		return uint64(b[1]) | uint64(b[2])<<8 | uint64(b[3])<<16, 4, true
	case 0xfe:
		if len(b) < 9 {
			return 0, 0, false
		}
		return binary.LittleEndian.Uint64(b[1:9]), 9, true
	default:
		return uint64(b[0]), 1, true
	}
}

// ClientCapabilities returns the 32-bit capability flags a client declared in
// its HandshakeResponse41 (first 4 bytes, little-endian). 0 if too short.
func ClientCapabilities(payload []byte) uint32 {
	if len(payload) < 4 {
		return 0
	}
	return binary.LittleEndian.Uint32(payload[0:4])
}

// ClearServerSSLCap clears the CLIENT_SSL bit in a server initial handshake
// (Protocol::HandshakeV10) packet payload, in place, so the client will not
// attempt a TLS upgrade. Returns true if the packet was recognized and edited.
//
// Layout up to the lower capability flags:
//
//	1   protocol version (0x0a)
//	s   server version (NUL-terminated)
//	4   thread id
//	8   auth-plugin-data-part-1
//	1   filler (0x00)
//	2   capability_flags_1 (lower 16 bits, little-endian)  <- CLIENT_SSL is here
func ClearServerSSLCap(payload []byte) bool {
	if len(payload) < 2 || payload[0] != 0x0a {
		return false
	}
	nul := bytes.IndexByte(payload[1:], 0)
	if nul < 0 {
		return false
	}
	pos := 1 + nul + 1 // past protocol version + server version + NUL
	pos += 4 + 8 + 1   // thread id + auth-plugin-data-1 + filler
	if pos+2 > len(payload) {
		return false
	}
	capLower := uint16(payload[pos]) | uint16(payload[pos+1])<<8
	if capLower&clientSSL == 0 {
		return false // already off
	}
	capLower &^= clientSSL
	payload[pos] = byte(capLower)
	payload[pos+1] = byte(capLower >> 8)
	return true
}

// ExtractSQLMySQL returns the SQL text of COM_QUERY / COM_STMT_PREPARE packets.
// (Back-compat wrapper; assumes no query-attributes header.)
func ExtractSQLMySQL(pkt MySQLPacket) (string, bool) {
	return ExtractSQLMySQLCaps(pkt, false)
}

// ExtractSQLMySQLCaps returns the SQL text of a COM_QUERY / COM_STMT_PREPARE
// packet, skipping the CLIENT_QUERY_ATTRIBUTES header when queryAttrs is true
// (MySQL 8.0.23+). Without this, the SQL would carry a binary attributes prefix
// (e.g. "\x00\x01SELECT ...") that corrupts logging and anchored matchers.
func ExtractSQLMySQLCaps(pkt MySQLPacket, queryAttrs bool) (string, bool) {
	if len(pkt.Payload) == 0 {
		return "", false
	}
	cmd := pkt.Payload[0]
	if cmd != MySQLComQuery && cmd != MySQLComStmtPrepare {
		return "", false
	}
	body := pkt.Payload[1:]

	// Only COM_QUERY carries the query-attributes header; COM_STMT_PREPARE does
	// not.
	if queryAttrs && cmd == MySQLComQuery {
		if rest, ok := skipQueryAttributes(body); ok {
			body = rest
		}
	}

	sql := strings.TrimRight(string(body), "\x00 \t\r\n")
	if sql == "" {
		return "", false
	}
	return sql, true
}

// skipQueryAttributes consumes the COM_QUERY query-attributes header and returns
// the remaining bytes (the SQL). Handles the common parameter_count==0 case
// exactly; for parameter_count>0 it conservatively skips the fixed header and
// returns the remainder (over-inclusive, never dropping the SQL).
func skipQueryAttributes(body []byte) ([]byte, bool) {
	paramCount, n1, ok := lenencInt(body)
	if !ok {
		return body, false
	}
	p := n1
	_, n2, ok := lenencInt(body[p:]) // parameter_set_count (always 1)
	if !ok {
		return body, false
	}
	p += n2
	if paramCount == 0 {
		if p > len(body) {
			return body, false
		}
		return body[p:], true
	}
	// parameter_count > 0: skip null bitmap + new_params_bind_flag, and (if set)
	// the type+name table. Values are variable-length; rather than decode every
	// type, return from just before them - the SQL still follows and matchers
	// remain over-inclusive. The mysql CLI uses parameter_count==0, so this path
	// is rare.
	bitmap := (int(paramCount) + 7) / 8
	if p+bitmap+1 > len(body) {
		return body, false
	}
	newBind := body[p+bitmap]
	p += bitmap + 1
	if newBind != 0 {
		for i := uint64(0); i < paramCount; i++ {
			if p+2 > len(body) {
				return body, false
			}
			p += 2 // param type + flag
			_, nn, ok := lenencInt(body[p:])
			if !ok {
				return body, false
			}
			nameLen, _, _ := lenencInt(body[p:])
			p += nn + int(nameLen)
			if p > len(body) {
				return body, false
			}
		}
	}
	if p > len(body) {
		return body, false
	}
	return body[p:], true
}

// ParseHandshakeResponse extracts (user, database) from a HandshakeResponse41.
// It also accepts the older HandshakeResponse320 shape.
func ParseHandshakeResponse(payload []byte) (string, string, bool) {
	if len(payload) < 32 {
		return "", "", false
	}
	caps := binary.LittleEndian.Uint32(payload[0:4])
	maxPacket := binary.LittleEndian.Uint32(payload[4:8])
	if maxPacket == 0 && caps == 0 {
		return "", "", false
	}
	pos := 32 // 4 caps + 4 maxpacket + 1 charset + 23 reserved
	if pos >= len(payload) {
		return "", "", false
	}
	// username (NUL-terminated)
	i := bytes.IndexByte(payload[pos:], 0)
	if i < 0 {
		return "", "", false
	}
	user := string(payload[pos : pos+i])
	pos += i + 1

	// auth response: 1-byte length (41) unless CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA
	if caps&0x00200000 == 0 { // not lenenc auth
		if pos >= len(payload) {
			return user, "", true
		}
		authLen := int(payload[pos])
		pos += 1 + authLen
	} else {
		// lenenc int: assume small (<251) single byte for typical sizes
		if pos < len(payload) {
			authLen := int(payload[pos])
			pos += 1 + authLen
		}
	}

	db := ""
	if caps&clientConnectWithDB != 0 && pos < len(payload) {
		j := bytes.IndexByte(payload[pos:], 0)
		if j >= 0 {
			db = string(payload[pos : pos+j])
		}
	}
	return user, db, user != ""
}

// ParseComInitDB returns the database switched to via COM_INIT_DB.
func ParseComInitDB(pkt MySQLPacket) (string, bool) {
	if len(pkt.Payload) < 2 || pkt.Payload[0] != MySQLComInitDB {
		return "", false
	}
	return string(pkt.Payload[1:]), true
}

// LooksLikeMySQL helps classify a raw first segment of a stream: a plausible
// MySQL packet has len LE < 16MB and a sane seq byte.
func LooksLikeMySQL(b []byte) bool {
	if len(b) < 5 {
		return false
	}
	length := u24(b[0:3])
	seq := b[3]
	return length <= 1<<22 && seq <= 4
}
