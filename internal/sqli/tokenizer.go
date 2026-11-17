// Package sqli implements DBGuard's SQL injection firewall: a small SQL
// lexer feeds a signature engine whose per-signature weights combine into a
// single confidence score that the pipeline compares against the configured
// threshold to allow or deny a statement.
//
// tokenizer.go holds the lexical layer. It is dialect-tolerant (MySQL and
// PostgreSQL quoting, line/block comments) and preserves case and byte
// offsets; callers that need case-insensitive matching lowercase token text
// themselves (see newScanCtx in signatures.go).
package sqli

import "strings"

// TokenKind classifies one lexical unit of a SQL statement.
type TokenKind int

const (
	// TokIdent is a keyword or identifier (including $1 placeholders'
	// alphabetic part and unicode identifiers).
	TokIdent TokenKind = iota
	// TokNumber is an integer, decimal, exponent or hex literal (0x1f).
	TokNumber
	// TokString is a quoted literal or identifier: '…', "…" or `…`,
	// including the surrounding quotes.
	TokString
	// TokComment is a --, # or /* */ comment, verbatim.
	TokComment
	// TokOperator is a comparison/arithmetic operator.
	TokOperator
	// TokPunct is structural punctuation: ( ) , ; . : ? @ [ ] and the like.
	TokPunct
)

// Token is one lexical unit: its kind, raw text (case preserved) and byte
// offset of the first character in the source statement.
type Token struct {
	Kind TokenKind
	Text string
	Pos  int
}

// twoCharOps are the maximal-munch two-character operators checked before
// single-character ones.
var twoCharOps = []string{"<=", ">=", "<>", "!=", "||", "->", "=>"}

// singleCharOps are the one-character operators.
const singleCharOps = "+-*/%=<>|&^~!"

// Tokenize lexes sql into a token slice. Unterminated strings and comments
// run to end of input (no error): the signature engine still sees whatever
// the attacker sent. Case and offsets are preserved.
func Tokenize(sql string) []Token {
	toks := make([]Token, 0, 16)
	i := 0
	for i < len(sql) {
		c := sql[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v':
			i++
		case c == '\'' || c == '"' || c == '`':
			text, next := scanQuoted(sql, i)
			toks = append(toks, Token{Kind: TokString, Text: text, Pos: i})
			i = next
		case c == '-' && i+1 < len(sql) && sql[i+1] == '-',
			c == '#': // MySQL line comment
			end := len(sql)
			if j := strings.IndexByte(sql[i:], '\n'); j >= 0 {
				end = i + j
			}
			toks = append(toks, Token{Kind: TokComment, Text: sql[i:end], Pos: i})
			i = end
		case c == '/' && i+1 < len(sql) && sql[i+1] == '*':
			end := len(sql)
			if j := strings.Index(sql[i+2:], "*/"); j >= 0 {
				end = i + 2 + j + 2
			}
			toks = append(toks, Token{Kind: TokComment, Text: sql[i:end], Pos: i})
			i = end
		case c >= '0' && c <= '9',
			c == '.' && i+1 < len(sql) && sql[i+1] >= '0' && sql[i+1] <= '9':
			j := i
			for j < len(sql) && isIdentChar(sql[j]) {
				j++
			}
			toks = append(toks, Token{Kind: TokNumber, Text: sql[i:j], Pos: i})
			i = j
		case isIdentStart(c):
			j := i
			for j < len(sql) && isIdentChar(sql[j]) {
				j++
			}
			toks = append(toks, Token{Kind: TokIdent, Text: sql[i:j], Pos: i})
			i = j
		default:
			if op := matchTwoChar(sql, i); op != "" {
				toks = append(toks, Token{Kind: TokOperator, Text: op, Pos: i})
				i += len(op)
				continue
			}
			if strings.IndexByte(singleCharOps, c) >= 0 {
				toks = append(toks, Token{Kind: TokOperator, Text: sql[i : i+1], Pos: i})
			} else {
				toks = append(toks, Token{Kind: TokPunct, Text: sql[i : i+1], Pos: i})
			}
			i++
		}
	}
	return toks
}

// scanQuoted consumes a quoted region starting at i (sql[i] is the quote
// character). Handles doubled-quote escaping (” or "" or “) and the
// MySQL backslash escape inside single-quoted strings. Returns the raw
// token text (quotes included) and the index just past it.
func scanQuoted(sql string, i int) (string, int) {
	q := sql[i]
	j := i + 1
	for j < len(sql) {
		switch {
		case sql[j] == q:
			if j+1 < len(sql) && sql[j+1] == q { // doubled quote escapes
				j += 2
				continue
			}
			return sql[i : j+1], j + 1
		case q == '\'' && sql[j] == '\\' && j+1 < len(sql):
			j += 2 // backslash escape (MySQL)
		default:
			j++
		}
	}
	return sql[i:], len(sql) // unterminated: run to end of input
}

// matchTwoChar returns the two-character operator at i, or "".
func matchTwoChar(sql string, i int) string {
	if i+1 >= len(sql) {
		return ""
	}
	pair := sql[i : i+2]
	for _, op := range twoCharOps {
		if pair == op {
			return op
		}
	}
	return ""
}

func isIdentStart(c byte) bool {
	return c == '_' || c >= 0x80 || // underscore + unicode bytes
		(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isIdentChar(c byte) bool {
	return isIdentStart(c) || (c >= '0' && c <= '9') || c == '$' || c == '.'
}
