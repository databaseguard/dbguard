package proto

// PostgreSQL Frontend/Backend protocol (v3) parsing.
//
// Reference: https://www.postgresql.org/docs/current/protocol-message-formats.html
//
// After startup, every message is:
//     byte      type ('Q' query, 'P' parse, 'B' bind, 'E' execute, ...)
//     int32     length (includes itself, excludes type byte)
//     payload
//
// The initial StartupMessage is: int32 length, int32 protocol (196608 = 3<<16),
// then NUL-separated key/value pairs, terminated by an empty string.

import (
	"bytes"
	"encoding/binary"
	"strings"
)

// PG protocol message types of interest.
const (
	PGMsgQuery         byte = 'Q'
	PGMsgParse         byte = 'P'
	PGMsgBind          byte = 'B'
	PGMsgExecute       byte = 'E'
	PGMsgSync          byte = 'S'
	PGMsgTerminate     byte = 'X'
	PGMsgErrorResponse byte = 'E' // backend direction, disambiguated by context
)

const pgProtocolVersion = 196608 // 3.0

// PGParser incrementally decodes a PostgreSQL frontend/backend byte stream.
type PGParser struct {
	buf      []byte
	startup  bool // still waiting for StartupMessage
	sawQuery bool
}

// NewPGParser creates a parser for a single connection stream.
func NewPGParser() *PGParser {
	return &PGParser{startup: true}
}

// Feed appends bytes and returns all complete messages decoded so far.
// Incomplete trailing data is retained for the next call.
func (p *PGParser) Feed(data []byte) []Message {
	p.buf = append(p.buf, data...)
	var out []Message
	for {
		if p.startup {
			// startup: int32 len + int32 version
			if len(p.buf) < 8 {
				return out
			}
			total := int(binary.BigEndian.Uint32(p.buf[0:4]))
			if total < 8 || total > 1<<20 {
				// not a startup message; treat as regular stream
				p.startup = false
				continue
			}
			if len(p.buf) < total {
				return out
			}
			proto := binary.BigEndian.Uint32(p.buf[4:8])
			if proto == pgProtocolVersion || proto>>16 == 3 {
				// consume startup; nothing to emit (params parsed separately)
				params := ParseStartup(bytes.Clone(p.buf[:total]))
				_ = params
				p.buf = p.buf[total:]
				p.startup = false
				continue
			}
			p.startup = false
			continue
		}
		if len(p.buf) < 5 {
			return out
		}
		mtype := p.buf[0]
		length := int(binary.BigEndian.Uint32(p.buf[1:5]))
		if length < 4 || length > 1<<22 { // 4MB sanity cap
			// desync: drop one byte and keep scanning
			p.buf = p.buf[1:]
			continue
		}
		total := 1 + length
		if len(p.buf) < total {
			return out
		}
		payload := bytes.Clone(p.buf[5:total])
		p.buf = p.buf[total:]
		if mtype == PGMsgQuery || mtype == PGMsgParse {
			p.sawQuery = true
		}
		out = append(out, Message{Type: mtype, Payload: payload})
	}
}

// SawQuery reports whether any frontend query was decoded (stream classifier).
func (p *PGParser) SawQuery() bool { return p.sawQuery }

// ParseStartup extracts key/value parameters (user, database, application_name)
// from a raw StartupMessage.
func ParseStartup(raw []byte) map[string]string {
	params := map[string]string{}
	if len(raw) < 8 {
		return params
	}
	body := raw[8:]
	parts := bytes.Split(body, []byte{0})
	for i := 0; i+1 < len(parts); i += 2 {
		k, v := string(parts[i]), string(parts[i+1])
		if k == "" && v == "" {
			break
		}
		params[k] = v
	}
	return params
}

// ExtractSQL returns the SQL statement from a Query ('Q') or Parse ('P')
// message payload.
func ExtractSQLPostgres(m Message) (string, bool) {
	switch m.Type {
	case PGMsgQuery:
		sql := cstring(m.Payload)
		if sql == "" {
			return "", false
		}
		return sql, true
	case PGMsgParse:
		// P: string name, string query, int16 nparams, params...
		if len(m.Payload) == 0 {
			return "", false
		}
		rest := m.Payload
		// skip prepared-statement name
		i := bytes.IndexByte(rest, 0)
		if i < 0 {
			return "", false
		}
		rest = rest[i+1:]
		sql := cstring(rest)
		if sql == "" {
			return "", false
		}
		return sql, true
	default:
		return "", false
	}
}

// ExtractTables does a light parse of table names referenced by FROM/INTO/
// UPDATE/JOIN clauses - enough for policy matching, not a full SQL AST.
func ExtractTables(sql string) []string {
	var out []string
	tokens := tokenize(sql)
	for i, t := range tokens {
		up := strings.ToUpper(t)
		switch up {
		case "FROM", "INTO", "UPDATE", "JOIN", "TABLE":
			if i+1 < len(tokens) {
				name := strings.Trim(tokens[i+1], `"`)
				if name != "" && !isSQLKeyword(name) && !strings.EqualFold(name, "SELECT") {
					out = append(out, name)
				}
			}
		}
	}
	return dedup(out)
}

// ExtractColumns returns referenced identifiers for column-level rules when
// the SQL text names them explicitly (best-effort, e.g. SELECT a, b FROM t).
func ExtractColumns(sql string) []string {
	up := strings.ToUpper(sql)
	idx := strings.Index(up, "SELECT")
	if idx != 0 {
		return nil
	}
	end := strings.Index(up, " FROM ")
	if end < 0 {
		return nil
	}
	sel := sql[len("SELECT"):end]
	if strings.Contains(sel, "*") {
		return nil
	}
	var out []string
	for _, part := range strings.Split(sel, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// strip alias and functions: "x.salary AS pay" -> salary
		if i := strings.LastIndex(strings.ToLower(part), " as "); i >= 0 {
			part = part[:i]
		}
		if i := strings.Index(part, "("); i >= 0 {
			continue // function call - skip
		}
		part = strings.Trim(part, `"`)
		if i := strings.LastIndex(part, "."); i >= 0 {
			part = part[i+1:]
		}
		part = strings.TrimSpace(part)
		if part != "" && !isSQLKeyword(part) {
			out = append(out, part)
		}
	}
	return dedup(out)
}

var sqlKeywords = map[string]bool{
	"SELECT": true, "FROM": true, "WHERE": true, "AND": true, "OR": true,
	"NOT": true, "NULL": true, "INSERT": true, "INTO": true, "VALUES": true,
	"UPDATE": true, "SET": true, "DELETE": true, "JOIN": true, "ON": true,
	"GROUP": true, "BY": true, "ORDER": true, "LIMIT": true, "OFFSET": true,
	"UNION": true, "ALL": true, "AS": true, "DISTINCT": true, "CASE": true,
	"WHEN": true, "THEN": true, "ELSE": true, "END": true, "TRUE": true,
	"FALSE": true, "IN": true, "EXISTS": true, "BETWEEN": true, "LIKE": true,
}

func isSQLKeyword(s string) bool { return sqlKeywords[strings.ToUpper(s)] }

// tokenize splits SQL into identifier/operator tokens (quotes respected).
func tokenize(sql string) []string {
	var toks []string
	var cur strings.Builder
	inS, inD := false, false // single/double quote
	inLC := false            // line comment
	flush := func() {
		if cur.Len() > 0 {
			toks = append(toks, cur.String())
			cur.Reset()
		}
	}
	for i := 0; i < len(sql); i++ {
		c := sql[i]
		if inLC {
			if c == '\n' {
				inLC = false
			}
			continue
		}
		switch {
		case inS:
			if c == '\'' {
				if i+1 < len(sql) && sql[i+1] == '\'' {
					i++
				} else {
					inS = false
				}
			}
			continue
		case inD:
			if c == '"' {
				inD = false
			}
			continue
		}
		switch c {
		case '\'':
			flush()
			inS = true
		case '"':
			flush()
			inD = true
		case '-', '/':
			if i+1 < len(sql) && sql[i+1] == c {
				flush()
				inLC = true
			} else {
				flush()
				toks = append(toks, string(c))
			}
		case ' ', '\t', '\n', '\r', '(', ')', ',', ';', '=', '+', '*', '<', '>':
			flush()
		default:
			cur.WriteByte(c)
		}
	}
	flush()
	return toks
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := in[:0]
	for _, s := range in {
		k := strings.ToLower(s)
		if !seen[k] {
			seen[k] = true
			out = append(out, s)
		}
	}
	return out
}

// cstring returns the NUL-terminated string at the start of b.
func cstring(b []byte) string {
	i := bytes.IndexByte(b, 0)
	if i < 0 {
		return strings.TrimRight(string(b), "\x00 \t\r\n")
	}
	return string(b[:i])
}
