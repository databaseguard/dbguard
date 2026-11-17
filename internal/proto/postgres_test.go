package proto

import (
	"encoding/binary"
	"testing"
)

// pgStartup builds a PostgreSQL StartupMessage (len, protocol 3.0, key/values).
func pgStartup(user, db string) []byte {
	params := "user\x00" + user + "\x00database\x00" + db + "\x00\x00"
	total := 8 + len(params)
	b := make([]byte, 4, total)
	binary.BigEndian.PutUint32(b, uint32(total))
	b = binary.BigEndian.AppendUint32(b, pgProtocolVersion)
	return append(b, params...)
}

// pgQuery builds a 'Q' (simple query) message.
func pgQuery(sql string) []byte {
	payload := append([]byte(sql), 0)
	total := 4 + len(payload)
	b := make([]byte, 0, 1+total)
	b = append(b, PGMsgQuery)
	b = binary.BigEndian.AppendUint32(b, uint32(total))
	return append(b, payload...)
}

// pgParse builds a 'P' (extended-protocol Parse) message.
func pgParse(name, sql string) []byte {
	payload := []byte(name + "\x00" + sql + "\x00")
	payload = binary.BigEndian.AppendUint16(payload, 0) // zero parameters
	total := 4 + len(payload)
	b := make([]byte, 0, 1+total)
	b = append(b, PGMsgParse)
	b = binary.BigEndian.AppendUint32(b, uint32(total))
	return append(b, payload...)
}

func TestPGStartupConsumedSilently(t *testing.T) {
	p := NewPGParser()
	msgs := p.Feed(pgStartup("alice", "appdb"))
	if len(msgs) != 0 {
		t.Fatalf("startup must not emit messages, got %d", len(msgs))
	}
	params := ParseStartup(pgStartup("alice", "appdb"))
	if params["user"] != "alice" || params["database"] != "appdb" {
		t.Fatalf("startup params parsed wrong: %v", params)
	}
	if p.SawQuery() {
		t.Fatal("no query seen yet")
	}
}

func TestPGSimpleQuery(t *testing.T) {
	p := NewPGParser()
	p.Feed(pgStartup("alice", "appdb"))
	msgs := p.Feed(pgQuery("SELECT 1"))
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	if msgs[0].Type != PGMsgQuery {
		t.Fatalf("type = %q, want 'Q'", msgs[0].Type)
	}
	sql, ok := ExtractSQL(msgs[0])
	if !ok || sql != "SELECT 1" {
		t.Fatalf("ExtractSQL = %q,%v", sql, ok)
	}
	if !p.SawQuery() {
		t.Fatal("SawQuery not set")
	}
}

func TestPGParseMessage(t *testing.T) {
	p := NewPGParser()
	p.Feed(pgStartup("bob", "billing"))
	msgs := p.Feed(pgParse("stmt1", "SELECT balance FROM accounts WHERE id=$1"))
	if len(msgs) != 1 {
		t.Fatalf("got %d messages, want 1", len(msgs))
	}
	sql, ok := ExtractSQL(msgs[0])
	if !ok || sql != "SELECT balance FROM accounts WHERE id=$1" {
		t.Fatalf("ExtractSQL = %q,%v", sql, ok)
	}
}

func TestPGIncrementalFeed(t *testing.T) {
	p := NewPGParser()
	p.Feed(pgStartup("alice", "db"))
	q := pgQuery("SELECT 'split'")
	if msgs := p.Feed(q[:7]); len(msgs) != 0 {
		t.Fatalf("partial feed emitted %d messages", len(msgs))
	}
	msgs := p.Feed(q[7:])
	if len(msgs) != 1 {
		t.Fatalf("completion feed emitted %d messages, want 1", len(msgs))
	}
	if sql, _ := ExtractSQL(msgs[0]); sql != "SELECT 'split'" {
		t.Fatalf("sql = %q", sql)
	}
}

func TestPGDesyncRecovery(t *testing.T) {
	p := NewPGParser()
	// binary garbage: header lengths exceed every sanity cap, so the parser
	// resynchronises byte-by-byte instead of giving up
	garbage := []byte{0xAB, 0xCD, 0xEF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06}
	if msgs := p.Feed(garbage); len(msgs) != 0 {
		t.Fatalf("garbage emitted %d messages", len(msgs))
	}
	msgs := p.Feed(pgQuery("SELECT 1"))
	if len(msgs) != 1 {
		t.Fatalf("recovery failed: got %d messages, want 1", len(msgs))
	}
	if sql, ok := ExtractSQL(msgs[0]); !ok || sql != "SELECT 1" {
		t.Fatalf("recovered sql = %q,%v", sql, ok)
	}
}

func TestExtractTables(t *testing.T) {
	cases := []struct {
		sql  string
		want []string
	}{
		{"SELECT ssn, salary FROM employees WHERE dept = 'eng'", []string{"employees"}},
		{"UPDATE employees SET salary = 1 WHERE id = 2", []string{"employees"}},
		{"INSERT INTO audit_log (note) VALUES ('x')", []string{"audit_log"}},
		{"SELECT a.x FROM t1 JOIN t2 ON t1.id = t2.id", []string{"t1", "t2"}},
		{"SELECT 1", nil},
	}
	for _, tc := range cases {
		got := ExtractTables(tc.sql)
		if len(got) != len(tc.want) {
			t.Fatalf("ExtractTables(%q) = %v, want %v", tc.sql, got, tc.want)
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Fatalf("ExtractTables(%q) = %v, want %v", tc.sql, got, tc.want)
			}
		}
	}
}

func TestExtractTablesSkipsQuotedStrings(t *testing.T) {
	// the literal contains SQL keywords that must not leak into the table list
	got := ExtractTables("SELECT * FROM orders WHERE note = 'FROM shadow_table'")
	if len(got) != 1 || got[0] != "orders" {
		t.Fatalf("got %v, want [orders]", got)
	}
}

func TestExtractColumns(t *testing.T) {
	got := ExtractColumns("SELECT ssn, salary FROM employees WHERE dept = 'eng'")
	if len(got) != 2 || got[0] != "ssn" || got[1] != "salary" {
		t.Fatalf("got %v, want [ssn salary]", got)
	}
	if got := ExtractColumns("SELECT * FROM employees"); got != nil {
		t.Fatalf("star select must yield nil, got %v", got)
	}
	if got := ExtractColumns("UPDATE employees SET salary = 1"); got != nil {
		t.Fatalf("non-SELECT must yield nil, got %v", got)
	}
	// aliased and schema-qualified columns are normalised
	if got := ExtractColumns("SELECT u.name AS who FROM users u"); len(got) != 1 || got[0] != "name" {
		t.Fatalf("alias handling wrong: %v", got)
	}
	if got := ExtractColumns("SELECT s.salary FROM emp.salarystaff s"); len(got) != 1 || got[0] != "salary" {
		t.Fatalf("qualified column wrong: %v", got)
	}
}

func TestExtractSQLRejectsOtherMessages(t *testing.T) {
	// 'S' (Sync) payload - not a query
	m := Message{Type: PGMsgSync, Payload: []byte("junk")}
	if _, ok := ExtractSQL(m); ok {
		t.Fatal("Sync must not yield SQL")
	}
	if _, ok := ExtractSQL(Message{Type: PGMsgQuery, Payload: []byte{0}}); ok {
		t.Fatal("empty query must not yield SQL")
	}
	if PGMsgQuery != 'Q' || PGMsgParse != 'P' || PGMsgSync != 'S' {
		t.Fatal("protocol message constants drifted")
	}
}
