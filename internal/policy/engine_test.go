package policy

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/databaseguard/dbguard/internal/events"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// decisionHas reports whether the decision carries action a.
func decisionHas(d Decision, a events.Action) bool {
	for _, x := range d.Actions {
		if x == a {
			return true
		}
	}
	return false
}

// writePolicy drops one policy YAML document into dir.
func writePolicy(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

// newEngine builds an Engine over a fresh temp policy directory.
func newEngine(t *testing.T, yamlDocs map[string]string) (*Engine, string) {
	t.Helper()
	dir := t.TempDir()
	names := make([]string, 0, len(yamlDocs))
	for name := range yamlDocs {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		writePolicy(t, dir, name, yamlDocs[name])
	}
	e := New(testLogger())
	if err := e.SetDirs([]string{dir}, false); err != nil {
		t.Fatalf("policy load: %v", err)
	}
	return e, dir
}

func pctx(sql, engine, user, ip string, tables ...string) *Context {
	return &Context{
		Engine: engine, User: user, ClientIP: ip, SQL: sql,
		Tables: tables, Now: time.Now(),
	}
}

const emptyPolicyYAML = `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: empty
spec:
  default_action: allow
  rules: []
`

const unionPolicyYAML = `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: union-block
spec:
  default_action: allow
  rules:
    - id: deny-union
      name: Union Select
      severity: critical
      query:
        pattern: '(?i)union\s+select'
      actions: [deny, alert]
`

func TestDefaultAllowWhenNoRules(t *testing.T) {
	e, _ := newEngine(t, map[string]string{"00-default.yaml": emptyPolicyYAML})
	dec := e.Evaluate(pctx("SELECT id FROM users", "postgres", "app", "10.0.0.1"))
	if !dec.Allowed {
		t.Fatalf("default verdict must allow: %+v", dec)
	}
	if !strings.Contains(dec.Reason, "default allow") {
		t.Fatalf("reason = %q", dec.Reason)
	}
	if dec.RuleIDs != nil || len(dec.Actions) != 0 {
		t.Fatalf("unexpected rule/action bookkeeping: %+v", dec)
	}
}

func TestQueryPatternDenies(t *testing.T) {
	e, _ := newEngine(t, map[string]string{"10-union.yaml": unionPolicyYAML})

	mal := e.Evaluate(pctx("SELECT 1 UNION SELECT cc FROM users", "postgres", "app", "10.0.0.1"))
	if mal.Allowed {
		t.Fatalf("malicious query allowed: %+v", mal)
	}
	if len(mal.RuleIDs) != 1 || mal.RuleIDs[0] != "deny-union" {
		t.Fatalf("rule attribution wrong: %v", mal.RuleIDs)
	}
	if !decisionHas(mal, events.ActDeny) || !decisionHas(mal, events.ActAlert) {
		t.Fatalf("actions wrong: %v", mal.Actions)
	}
	if mal.Severity != events.SevCritical {
		t.Fatalf("severity = %s, want critical", mal.Severity)
	}

	clean := e.Evaluate(pctx("SELECT id FROM users WHERE id = 1", "postgres", "app", "10.0.0.1"))
	if !clean.Allowed {
		t.Fatalf("clean query denied: %+v", clean)
	}
}

func TestEngineFilter(t *testing.T) {
	e, _ := newEngine(t, map[string]string{"10-eng.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: engine-scope
spec:
  default_action: allow
  rules:
    - id: pg-only-deny
      name: Postgres only
      severity: high
      engines: [postgres]
      actions: [deny]
`})
	if dec := e.Evaluate(pctx("SELECT 1", "mysql", "app", "10.0.0.1")); !dec.Allowed {
		t.Fatalf("postgres rule must be ignored for mysql context: %+v", dec)
	}
	if dec := e.Evaluate(pctx("SELECT 1", "postgres", "app", "10.0.0.1")); dec.Allowed {
		t.Fatalf("postgres rule must fire for postgres context: %+v", dec)
	}
}

func TestUsersFilter(t *testing.T) {
	e, _ := newEngine(t, map[string]string{"10-users.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: user-scope
spec:
  default_action: allow
  rules:
    - id: app-rw-deny
      name: app_rw restricted
      users: [app_rw]
      actions: [deny]
`})
	if dec := e.Evaluate(pctx("SELECT 1", "postgres", "reporting", "10.0.0.1")); !dec.Allowed {
		t.Fatalf("other users must pass: %+v", dec)
	}
	if dec := e.Evaluate(pctx("SELECT 1", "postgres", "app_rw", "10.0.0.1")); dec.Allowed {
		t.Fatalf("listed user must be denied: %+v", dec)
	}
}

func TestClientsCIDR(t *testing.T) {
	e, _ := newEngine(t, map[string]string{"10-clients.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: client-scope
spec:
  default_action: allow
  rules:
    - id: corp-range
      clients: ["10.0.0.0/8"]
      actions: [deny]
`})
	if dec := e.Evaluate(pctx("SELECT 1", "postgres", "app", "10.1.2.3")); dec.Allowed {
		t.Fatal("10.1.2.3 must match 10.0.0.0/8")
	}
	if dec := e.Evaluate(pctx("SELECT 1", "postgres", "app", "192.168.1.1")); !dec.Allowed {
		t.Fatal("192.168.1.1 must not match 10.0.0.0/8")
	}

	e2, _ := newEngine(t, map[string]string{"10-clients.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: host-scope
spec:
  default_action: allow
  rules:
    - id: single-host
      clients: ["192.168.1.1/32"]
      actions: [deny]
`})
	if dec := e2.Evaluate(pctx("SELECT 1", "postgres", "app", "192.168.1.1")); dec.Allowed {
		t.Fatal("exact host must be denied")
	}
	if dec := e2.Evaluate(pctx("SELECT 1", "postgres", "app", "192.168.1.2")); !dec.Allowed {
		t.Fatal("neighbour host must pass")
	}
}

func TestTablesAndColumns(t *testing.T) {
	e, _ := newEngine(t, map[string]string{"10-objects.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: object-scope
spec:
  default_action: allow
  rules:
    - id: customers-guard
      tables: [customers]
      actions: [deny]
    - id: ssn-guard
      columns: [ssn]
      actions: [deny]
`})
	// table matcher
	if dec := e.Evaluate(pctx("SELECT * FROM customers", "postgres", "app", "10.0.0.1", "customers")); dec.Allowed {
		t.Fatal("customers table must be denied")
	}
	if dec := e.Evaluate(pctx("SELECT * FROM orders", "postgres", "app", "10.0.0.1", "orders")); !dec.Allowed {
		t.Fatal("other tables must pass")
	}
	// column matcher (columns come from the enrich stage's parse)
	dec := e.Evaluate(&Context{
		Engine: "postgres", User: "app", ClientIP: "10.0.0.1",
		SQL: "SELECT ssn FROM people", Columns: []string{"ssn"}, Now: time.Now(),
	})
	if dec.Allowed {
		t.Fatalf("ssn column must be denied: %+v", dec)
	}
	dec = e.Evaluate(&Context{
		Engine: "postgres", User: "app", ClientIP: "10.0.0.1",
		SQL: "SELECT name FROM people", Columns: []string{"name"}, Now: time.Now(),
	})
	if !dec.Allowed {
		t.Fatalf("non-ssn column must pass: %+v", dec)
	}
}

func TestDefaultDeny(t *testing.T) {
	e, _ := newEngine(t, map[string]string{"00-deny.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: closed-by-default
spec:
  default_action: deny
  rules: []
`})
	dec := e.Evaluate(pctx("SELECT 1", "postgres", "app", "10.0.0.1"))
	if dec.Allowed {
		t.Fatalf("default deny verdict must deny: %+v", dec)
	}
	if !strings.Contains(dec.Reason, "default deny") {
		t.Fatalf("reason = %q", dec.Reason)
	}
}

// TestRateLimit: events 2 / window 1m - first two requests pass, the third
// is denied with a rate-specific reason.
func TestRateLimit(t *testing.T) {
	e, _ := newEngine(t, map[string]string{"10-rate.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: rate-guard
spec:
  default_action: allow
  rules:
    - id: rl-select
      name: Rate limit select
      rate:
        events: 2
        window: 1m
      actions: [alert]
`})
	base := time.Now()
	want := []bool{true, true, false}
	for i, allow := range want {
		ctx := &Context{
			Engine: "postgres", User: "app", ClientIP: "10.0.0.1",
			SQL: "SELECT 1", Now: base.Add(time.Duration(i) * time.Second),
		}
		dec := e.Evaluate(ctx)
		if dec.Allowed != allow {
			t.Fatalf("request %d: allowed = %v, want %v (%+v)", i+1, dec.Allowed, allow, dec)
		}
		if !allow {
			if !strings.Contains(dec.Reason, "rate") {
				t.Fatalf("denial reason must mention rate: %q", dec.Reason)
			}
			if !decisionHas(dec, events.ActAlert) {
				t.Fatalf("rate denial must carry the rule actions: %v", dec.Actions)
			}
		}
	}
}

// TestTwoPoliciesMergeInFilenameOrder: alert rule from 10-*.yaml annotates
// first, deny rule from 20-*.yaml stops evaluation second.
func TestTwoPoliciesMergeInFilenameOrder(t *testing.T) {
	e, _ := newEngine(t, map[string]string{
		"10-alert.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: alert-first
spec:
  default_action: allow
  rules:
    - id: alert-union
      severity: low
      query:
        pattern: 'union\s+select'
        case_insensitive: true
      actions: [alert]
`,
		"20-deny.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: deny-second
spec:
  default_action: allow
  rules:
    - id: deny-union
      severity: high
      query:
        pattern: '(?i)union\s+select'
      actions: [deny]
`,
	})
	dec := e.Evaluate(pctx("SELECT 1 UNION SELECT pw FROM users", "postgres", "app", "10.0.0.1"))
	if dec.Allowed {
		t.Fatalf("deny rule must win: %+v", dec)
	}
	if len(dec.RuleIDs) != 2 || dec.RuleIDs[0] != "alert-union" || dec.RuleIDs[1] != "deny-union" {
		t.Fatalf("rules must evaluate in filename order: %v", dec.RuleIDs)
	}
	if !decisionHas(dec, events.ActAlert) || !decisionHas(dec, events.ActDeny) {
		t.Fatalf("actions from both rules must surface: %v", dec.Actions)
	}
}

// TestSeverityAggregation: multiple alert-only rules must surface the worst
// severity without denying.
func TestSeverityAggregation(t *testing.T) {
	e, _ := newEngine(t, map[string]string{
		"10-low.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: low-note
spec:
  default_action: allow
  rules:
    - id: low-watch
      severity: low
      actions: [alert]
`,
		"20-crit.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata:
  name: crit-watch
spec:
  default_action: allow
  rules:
    - id: crit-watch
      severity: critical
      actions: [alert]
`,
	})
	dec := e.Evaluate(pctx("SELECT 1", "postgres", "app", "10.0.0.1"))
	if !dec.Allowed {
		t.Fatalf("alert-only rules must not deny: %+v", dec)
	}
	if dec.Severity != events.SevCritical {
		t.Fatalf("severity = %s, want critical (worst of matched rules)", dec.Severity)
	}
	if len(dec.RuleIDs) != 2 {
		t.Fatalf("both rules must match: %v", dec.RuleIDs)
	}
}

// TestRateLimitThrottle verifies a rate rule allows up to N matches per window
// and denies the rest - and does NOT deny while under the limit (regression:
// rate rules used to deny on every match).
func TestRateLimitThrottle(t *testing.T) {
	e, _ := newEngine(t, map[string]string{"r.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata: {name: rl}
spec:
  default_action: allow
  rules:
    - id: rl
      clients: [0.0.0.0/0]
      rate: {events: 3, window: 1m}
      actions: [deny, alert]`})
	now := time.Now()
	var allowed, denied int
	for i := 0; i < 5; i++ {
		d := e.Evaluate(&Context{Engine: "postgres", ClientIP: "10.0.0.1", SQL: "SELECT 1", Now: now})
		if d.Allowed {
			allowed++
		} else {
			denied++
		}
	}
	if allowed != 3 || denied != 2 {
		t.Fatalf("rate limit: allowed=%d denied=%d, want 3/2", allowed, denied)
	}
}

// TestKeywordAnyOf verifies query.keywords is ANY-of (matches if the SQL
// contains at least one listed substring), not ALL-of (regression: a rule
// listing several file-primitive keywords only matched text containing them
// all, so it never fired).
func TestKeywordAnyOf(t *testing.T) {
	e, _ := newEngine(t, map[string]string{"k.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata: {name: k}
spec:
  default_action: allow
  rules:
    - id: fileprim
      query:
        keywords: [into outfile, load_file, lo_import]
        case_insensitive: true
      actions: [deny, alert]`})
	deny := e.Evaluate(&Context{Engine: "mysql", SQL: "SELECT * INTO OUTFILE '/x' FROM u", Now: time.Now()})
	if deny.Allowed {
		t.Fatal("expected DENY: query contains one of the keywords (into outfile)")
	}
	allow := e.Evaluate(&Context{Engine: "mysql", SQL: "SELECT id FROM products", Now: time.Now()})
	if !allow.Allowed {
		t.Fatal("expected ALLOW: query contains none of the keywords")
	}
}

// TestAllowlistDefaultDeny verifies that in default_action: deny (zero-trust
// allowlist) mode a matching rule with an explicit allow action PERMITS the
// query and short-circuits - and everything else is denied. (Regression: allow
// actions were ignored, so matching allow rules still hit the default deny.)
func TestAllowlistDefaultDeny(t *testing.T) {
	e, _ := newEngine(t, map[string]string{"a.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata: {name: allowlist}
spec:
  default_action: deny
  rules:
    - id: allow-app-selects
      users: [app_rw]
      query: {pattern: '(?i)^\s*select'}
      actions: [allow]`})
	now := time.Now()
	if d := e.Evaluate(&Context{Engine: "postgres", User: "app_rw", SQL: "SELECT id FROM t", Now: now}); !d.Allowed {
		t.Fatal("app_rw SELECT should be ALLOWED by the allowlist rule")
	}
	if d := e.Evaluate(&Context{Engine: "postgres", User: "app_rw", SQL: "DELETE FROM t", Now: now}); d.Allowed {
		t.Fatal("app_rw DELETE should be DENIED (not a SELECT, default deny)")
	}
	if d := e.Evaluate(&Context{Engine: "postgres", User: "other", SQL: "SELECT id FROM t", Now: now}); d.Allowed {
		t.Fatal("other user should be DENIED (not in allowlist)")
	}
}

// TestRateLimitEmptyClientIP verifies a rate rule scoped to 0.0.0.0/0 throttles
// queries whose client IP is unknown (empty) - e.g. local queries captured at
// the DB backend via uprobe. (Regression: an empty IP failed the CIDR match, so
// catch-all rate rules never triggered - the demo-rate 9-over-5 "allowed=9".)
func TestRateLimitEmptyClientIP(t *testing.T) {
	e, _ := newEngine(t, map[string]string{"r.yaml": `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata: {name: rl}
spec:
  default_action: allow
  rules:
    - id: rl
      clients: [0.0.0.0/0]
      rate: {events: 5, window: 1m}
      actions: [deny, alert]`})
	now := time.Now()
	var a, d int
	for i := 0; i < 9; i++ {
		if e.Evaluate(&Context{Engine: "postgres", ClientIP: "", SQL: "SELECT 1", Now: now}).Allowed {
			a++
		} else {
			d++
		}
	}
	if a != 5 || d != 4 {
		t.Fatalf("empty-IP rate: allowed=%d denied=%d, want 5/4", a, d)
	}
}
