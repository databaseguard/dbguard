// Package proto implements wire-protocol parsing for PostgreSQL (v3
// Frontend/Backend) and MySQL (Client/Server). Parsers are incremental:
// feed TCP segments, get complete protocol messages. They power the
// user-space pipeline, the lineage correlator and unit/integration tests;
// kernel-side counterparts live in bpf/src/sqli_firewall.bpf.c.
package proto

// Engine identifies a database backend.
type Engine string

const (
	EnginePostgres Engine = "postgres"
	EngineMySQL    Engine = "mysql"
	EngineSQLite   Engine = "sqlite"
	EngineUnknown  Engine = "unknown"
)

// PortHints are default ports used for engine guessing.
const (
	DefaultPostgresPort = 5432
	DefaultMySQLPort    = 3306
)

// GuessEngine classifies traffic by server port.
func GuessEngine(serverPort uint16) Engine {
	switch int(serverPort) {
	case DefaultPostgresPort:
		return EnginePostgres
	case DefaultMySQLPort:
		return EngineMySQL
	default:
		return EngineUnknown
	}
}

// Message is one decoded PostgreSQL protocol message.
type Message struct {
	Type    byte
	Payload []byte
}

// MySQLPacket is one decoded MySQL client/server packet.
type MySQLPacket struct {
	Seq     byte
	Payload []byte
}

// ExtractSQL returns the SQL text carried by a decoded protocol unit,
// dispatching on the concrete type: a PostgreSQL Message ('Q'/'P') or a
// MySQL packet (COM_QUERY / COM_STMT_PREPARE). It is the engine-agnostic
// entry point used by the pipeline and tests; ExtractSQLPostgres and
// ExtractSQLMySQL remain available when the engine is already known.
func ExtractSQL(unit any) (string, bool) {
	switch u := unit.(type) {
	case Message:
		return ExtractSQLPostgres(u)
	case *Message:
		if u == nil {
			return "", false
		}
		return ExtractSQLPostgres(*u)
	case MySQLPacket:
		return ExtractSQLMySQL(u)
	case *MySQLPacket:
		if u == nil {
			return "", false
		}
		return ExtractSQLMySQL(*u)
	default:
		return "", false
	}
}

// u24 reads a 3-byte little-endian length (MySQL header convention).
func u24(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16
}

// clamp returns b bounded to n bytes.
func clamp(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

// isSQLText heuristically reports whether s looks like SQL text (printable
// ASCII with SQL-ish keywords), used to reject binary garbage.
func isSQLText(s []byte) bool {
	if len(s) < 4 {
		return false
	}
	printable := 0
	for _, c := range clamp(s, 256) {
		if c == '\n' || c == '\r' || c == '\t' || (c >= 0x20 && c < 0x7f) {
			printable++
		}
	}
	return printable*4 >= len(s)*3
}
