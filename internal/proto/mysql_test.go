package proto

import (
	"encoding/binary"
	"testing"
)

// mysqlFrame prefixes a payload with the MySQL packet header: 3-byte
// little-endian payload length plus one sequence byte.
func mysqlFrame(payload []byte, seq byte) []byte {
	n := len(payload)
	out := make([]byte, 4, 4+n)
	out[0] = byte(n)
	out[1] = byte(n >> 8)
	out[2] = byte(n >> 16)
	out[3] = seq
	return append(out, payload...)
}

func mysqlComQuery(sql string) []byte {
	return mysqlFrame(append([]byte{MySQLComQuery}, sql...), 0)
}

func mysqlComStmtPrepare(sql string) []byte {
	return mysqlFrame(append([]byte{MySQLComStmtPrepare}, sql...), 0)
}

func mysqlComInitDB(db string) []byte {
	return mysqlFrame(append([]byte{MySQLComInitDB}, db...), 0)
}

// mysqlHandshakePayload builds a HandshakeResponse41 body: capability flags
// (CLIENT_PROTOCOL_41 | CLIENT_CONNECT_WITH_DB | CLIENT_SECURE_CONNECTION),
// max packet size, charset, 23 reserved bytes, NUL-terminated user, 20-byte
// auth response and NUL-terminated database.
func mysqlHandshakePayload(user, db string) []byte {
	const (
		clientProtocol41 = 0x00000200
		clientSecureConn = 0x00008000
	)
	caps := uint32(clientProtocol41 | clientConnectWithDB | clientSecureConn)
	b := make([]byte, 0, 64)
	b = binary.LittleEndian.AppendUint32(b, caps)
	b = binary.LittleEndian.AppendUint32(b, 1<<24) // max packet size
	b = append(b, 0x21)                            // charset utf8_general_ci
	b = append(b, make([]byte, 23)...)             // reserved
	b = append(b, user...)
	b = append(b, 0)
	b = append(b, 20) // auth response length
	b = append(b, make([]byte, 20)...)
	b = append(b, db...)
	b = append(b, 0)
	return b
}

func TestMySQLHandshakeThenQuery(t *testing.T) {
	p := NewMySQLParser()
	if got := p.Feed(mysqlFrame(mysqlHandshakePayload("dbguard", "dbguard_test"), 1)); len(got) != 0 {
		t.Fatalf("handshake must not emit packets, got %d", len(got))
	}
	if p.SawQuery() {
		t.Fatal("no query seen yet")
	}
	pkts := p.Feed(mysqlComQuery("SELECT * FROM users"))
	if len(pkts) != 1 {
		t.Fatalf("got %d packets, want 1", len(pkts))
	}
	if !IsClientCommand(pkts[0].Payload) {
		t.Fatal("COM_QUERY payload not recognised as client command")
	}
	sql, ok := ExtractSQL(pkts[0])
	if !ok || sql != "SELECT * FROM users" {
		t.Fatalf("ExtractSQL = %q,%v", sql, ok)
	}
	if !p.SawQuery() {
		t.Fatal("SawQuery not set")
	}
}

func TestMySQLStmtPrepare(t *testing.T) {
	p := NewMySQLParser()
	p.Feed(mysqlFrame(mysqlHandshakePayload("dbguard", "dbguard_test"), 1))
	pkts := p.Feed(mysqlComStmtPrepare("SELECT balance FROM accounts WHERE id = ?"))
	if len(pkts) != 1 {
		t.Fatalf("got %d packets, want 1", len(pkts))
	}
	sql, ok := ExtractSQL(pkts[0])
	if !ok || sql != "SELECT balance FROM accounts WHERE id = ?" {
		t.Fatalf("ExtractSQL = %q,%v", sql, ok)
	}
	// non-command payloads yield no SQL
	pkt := pkts[0]
	pkt.Payload = []byte{MySQLComPing}
	if _, ok := ExtractSQL(pkt); ok {
		t.Fatal("COM_PING must not yield SQL")
	}
}

func TestMySQLParseHandshakeResponse(t *testing.T) {
	user, db, ok := ParseHandshakeResponse(mysqlHandshakePayload("dbguard", "dbguard_test"))
	if !ok || user != "dbguard" || db != "dbguard_test" {
		t.Fatalf("ParseHandshakeResponse = %q,%q,%v", user, db, ok)
	}
	// too-short / empty headers are rejected
	if _, _, ok := ParseHandshakeResponse(nil); ok {
		t.Fatal("nil payload accepted")
	}
	if _, _, ok := ParseHandshakeResponse(make([]byte, 31)); ok {
		t.Fatal("31-byte payload accepted")
	}
	// without CLIENT_CONNECT_WITH_DB the database stays empty
	raw := mysqlHandshakePayload("alice", "ignored")
	binary.LittleEndian.PutUint32(raw[0:4], 0x00000200) // drop the DB flag
	user, db, ok = ParseHandshakeResponse(raw)
	if !ok || user != "alice" || db != "" {
		t.Fatalf("no-db parse = %q,%q,%v", user, db, ok)
	}
}

func TestMySQLParseComInitDB(t *testing.T) {
	pkt := MySQLPacket{Seq: 0, Payload: append([]byte{MySQLComInitDB}, "dbguard_test"...)}
	db, ok := ParseComInitDB(pkt)
	if !ok || db != "dbguard_test" {
		t.Fatalf("ParseComInitDB = %q,%v", db, ok)
	}
	if _, ok := ParseComInitDB(MySQLPacket{Payload: []byte{MySQLComQuery}}); ok {
		t.Fatal("COM_QUERY parsed as COM_INIT_DB")
	}
}

func TestMySQLLooksLikeMySQL(t *testing.T) {
	if !LooksLikeMySQL(mysqlComQuery("SELECT 1")) {
		t.Fatal("valid COM_QUERY frame rejected")
	}
	if LooksLikeMySQL([]byte{0x51, 0x00, 0x00}) { // too short
		t.Fatal("short buffer accepted")
	}
	// A PostgreSQL 'Q' (simple query) message whose 4 MiB+ length field sits
	// where MySQL expects its 24-bit length: the sanity cap must reject it.
	pgBigQuery := []byte{'Q', 0x00, 0x40, 0x00, 0x00, 'S', 'E', 'L'}
	if LooksLikeMySQL(pgBigQuery) {
		t.Fatal("oversized PostgreSQL message classified as MySQL")
	}
	// A sequence byte above 4 is equally impossible in a MySQL header.
	if LooksLikeMySQL([]byte{0x13, 0x00, 0x00, 0x2D, 0x03}) {
		t.Fatal("impossible sequence byte accepted")
	}
}

func TestMySQLIncrementalFeed(t *testing.T) {
	p := NewMySQLParser()
	p.Feed(mysqlFrame(mysqlHandshakePayload("dbguard", "dbguard_test"), 1))
	pkt := mysqlComQuery("SELECT 'split'")
	if got := p.Feed(pkt[:6]); len(got) != 0 {
		t.Fatalf("partial feed emitted %d packets", len(got))
	}
	got := p.Feed(pkt[6:])
	if len(got) != 1 {
		t.Fatalf("completion feed emitted %d packets, want 1", len(got))
	}
	if sql, _ := ExtractSQL(got[0]); sql != "SELECT 'split'" {
		t.Fatalf("sql = %q", sql)
	}
}
