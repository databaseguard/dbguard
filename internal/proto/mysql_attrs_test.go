package proto

import "testing"

// A COM_QUERY with the CLIENT_QUERY_ATTRIBUTES header (parameter_count=0,
// parameter_set_count=1) must yield the clean SQL with no binary prefix.
func TestExtractSQLMySQLQueryAttributes(t *testing.T) {
	sql := "SELECT id FROM customers UNION SELECT ssn FROM customers"
	// 0x03 COM_QUERY, then lenenc 0 (param_count), lenenc 1 (param_set_count)
	payload := append([]byte{MySQLComQuery, 0x00, 0x01}, []byte(sql)...)

	got, ok := ExtractSQLMySQLCaps(MySQLPacket{Payload: payload}, true)
	if !ok {
		t.Fatal("expected SQL extracted")
	}
	if got != sql {
		t.Fatalf("query-attributes header not stripped:\n got %q\nwant %q", got, sql)
	}

	// Without the queryAttrs flag the header bytes would leak in as a prefix.
	leaky, _ := ExtractSQLMySQLCaps(MySQLPacket{Payload: payload}, false)
	if leaky == sql {
		t.Fatal("expected a corrupted prefix when queryAttrs=false (guards the fix)")
	}
}

// A plain COM_QUERY (no attributes) must still parse with queryAttrs=false.
func TestExtractSQLMySQLPlain(t *testing.T) {
	sql := "SELECT 1"
	payload := append([]byte{MySQLComQuery}, []byte(sql)...)
	got, ok := ExtractSQLMySQL(MySQLPacket{Payload: payload})
	if !ok || got != sql {
		t.Fatalf("plain COM_QUERY parse failed: got %q ok=%v", got, ok)
	}
}

// ClearServerSSLCap must clear CLIENT_SSL (1<<11) in a HandshakeV10 packet.
func TestClearServerSSLCap(t *testing.T) {
	// Build a minimal HandshakeV10: 0x0a, "8.0.46"\0, 4 thread id, 8 auth1,
	// 1 filler, 2 cap_lower (with CLIENT_SSL set), then trailing bytes.
	p := []byte{0x0a}
	p = append(p, []byte("8.0.46")...)
	p = append(p, 0)                              // NUL
	p = append(p, 1, 2, 3, 4)                     // thread id
	p = append(p, 10, 11, 12, 13, 14, 15, 16, 17) // auth-plugin-data-1
	p = append(p, 0)                              // filler
	capPos := len(p)
	capLow := uint16(0xFFFF) // all lower bits incl. CLIENT_SSL set
	p = append(p, byte(capLow), byte(capLow>>8))
	p = append(p, 0x21, 0x00, 0x00) // charset + status (padding)

	if capLow&(1<<11) == 0 {
		t.Fatal("test setup: CLIENT_SSL not set")
	}
	if !ClearServerSSLCap(p) {
		t.Fatal("ClearServerSSLCap returned false on a valid handshake")
	}
	got := uint16(p[capPos]) | uint16(p[capPos+1])<<8
	if got&(1<<11) != 0 {
		t.Fatalf("CLIENT_SSL not cleared: cap_lower=0x%04x", got)
	}
	// A non-handshake packet is left alone.
	if ClearServerSSLCap([]byte{0xff, 0x00}) {
		t.Fatal("ClearServerSSLCap should reject a non-handshake packet")
	}
}
