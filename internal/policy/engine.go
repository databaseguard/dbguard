package policy

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/databaseguard/dbguard/internal/events"
	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Context is what a rule evaluates against - built by the pipeline from an
// enriched event.
type Context struct {
	Engine         string // postgres|mysql|sqlite
	User           string
	Database       string
	ClientIP       string
	SQL            string
	Tables         []string
	Columns        []string
	SessionID      uint64
	PID            uint32
	Labels         map[string]string
	CiliumIdentity string   // Cilium security-identity id for ClientIP (optional)
	CiliumLabels   []string // the identity's labels, e.g. "k8s:app=api-server"
	Now            time.Time
}

// Decision is the engine verdict for a Context.
type Decision struct {
	Allowed   bool
	Actions   []events.Action
	RuleIDs   []string
	RuleNames []string
	Severity  events.Severity
	Reason    string
}

// Engine evaluates ordered rules from one or more policy documents.
type Engine struct {
	mu       sync.RWMutex
	policies []*Policy
	entries  []compiledRule
	dirs     []string
	watch    bool
	logger   *slog.Logger

	rates *rateLimiter

	stopWatch chan struct{}
	reloadCh  chan struct{}
}

// compiledRule pairs a rule with precompiled matchers.
type compiledRule struct {
	policy string
	rule   Rule
	re     *regexp.Regexp
	keyws  []string
	cidrs  []netip.Prefix
}

// New creates an empty engine.
func New(logger *slog.Logger) *Engine {
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		logger:    logger,
		rates:     newRateLimiter(),
		stopWatch: make(chan struct{}),
		reloadCh:  make(chan struct{}, 1),
	}
}

// LoadDir loads every *.yaml / *.yml policy document under dir (non-recursively,
// sorted by filename so 00-default.yaml evaluates before 50-tenant.yaml).
func (e *Engine) LoadDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("policy: read dir %s: %w", dir, err)
	}
	var loaded int
	for _, ent := range entries {
		if ent.IsDir() {
			continue
		}
		n := ent.Name()
		if !strings.HasSuffix(n, ".yaml") && !strings.HasSuffix(n, ".yml") {
			continue
		}
		path := filepath.Join(dir, n)
		if err := e.LoadFile(path); err != nil {
			return err
		}
		loaded++
	}
	if loaded > 0 {
		e.rebuild()
	}
	return nil
}

// LoadFile parses and stages one policy document.
func (e *Engine) LoadFile(path string) error {
	raw, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("policy: read %s: %w", path, err)
	}
	var p Policy
	if err := yaml.Unmarshal(raw, &p); err != nil {
		return fmt.Errorf("policy: parse %s: %w", path, err)
	}
	if p.Kind != "" && p.Kind != "DbGuardPolicy" {
		return fmt.Errorf("policy: %s: kind %q unsupported (want DbGuardPolicy)", path, p.Kind)
	}
	if p.Metadata.Name == "" {
		return fmt.Errorf("policy: %s: metadata.name is required", path)
	}
	if err := validatePolicy(&p); err != nil {
		return fmt.Errorf("policy: %s: %w", path, err)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	// replace same-named policy (hot reload semantics)
	replaced := false
	for i, old := range e.policies {
		if old.Metadata.Name == p.Metadata.Name {
			e.policies[i] = &p
			replaced = true
			break
		}
	}
	if !replaced {
		e.policies = append(e.policies, &p)
	}
	return nil
}

// validatePolicy compiles regexes and validates fields up-front.
func validatePolicy(p *Policy) error {
	seen := map[string]bool{}
	for _, r := range p.Spec.Rules {
		if r.ID == "" {
			return fmt.Errorf("rule without id in policy %q", p.Metadata.Name)
		}
		if seen[r.ID] {
			return fmt.Errorf("duplicate rule id %q in policy %q", r.ID, p.Metadata.Name)
		}
		seen[r.ID] = true
		if r.Query != nil && r.Query.Pattern != "" {
			if _, err := regexp.Compile(r.Query.Pattern); err != nil {
				return fmt.Errorf("rule %s: bad pattern: %w", r.ID, err)
			}
		}
		for _, a := range r.Actions {
			if !events.IsValidAction(a) {
				return fmt.Errorf("rule %s: unknown action %q", r.ID, a)
			}
		}
		if r.Rate != nil {
			if _, err := parseWindow(r.Rate.Window); err != nil {
				return fmt.Errorf("rule %s: %w", r.ID, err)
			}
		}
		if r.Severity != "" {
			_ = events.ParseSeverity(r.Severity)
		}
	}
	return nil
}

func parseWindow(w string) (time.Duration, error) {
	if w == "" {
		return time.Minute, nil
	}
	d, err := time.ParseDuration(w)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("bad rate window %q", w)
	}
	return d, nil
}

// rebuild recompiles staged policies into entries. Caller must hold e.mu for
// write or call after dropping it (uses double-checked pattern via Lock).
func (e *Engine) rebuild() {
	e.mu.Lock()
	defer e.mu.Unlock()
	var entries []compiledRule
	for _, p := range e.policies {
		for _, r := range p.Spec.Rules {
			cr := compiledRule{policy: p.Metadata.Name, rule: r}
			if r.Query != nil && r.Query.Pattern != "" {
				pat := r.Query.Pattern
				if r.Query.CaseInsensitive && !strings.HasPrefix(pat, "(?i)") {
					pat = "(?i)" + pat
				}
				cr.re = regexp.MustCompile(pat)
			}
			if r.Query != nil {
				for _, k := range r.Query.Keywords {
					if r.Query.CaseInsensitive {
						cr.keyws = append(cr.keyws, strings.ToLower(k))
					} else {
						cr.keyws = append(cr.keyws, k)
					}
				}
			}
			for _, c := range r.Clients {
				if !strings.Contains(c, "/") {
					bits := 32
					if strings.Contains(c, ":") {
						bits = 128
					}
					c = c + "/" + fmt.Sprint(bits)
				}
				if pfx, err := netip.ParsePrefix(c); err == nil {
					cr.cidrs = append(cr.cidrs, pfx)
				}
			}
			entries = append(entries, cr)
		}
	}
	e.entries = entries
}

// Reload re-reads all configured dirs (used by the watcher and the API).
func (e *Engine) Reload() error {
	e.mu.RLock()
	dirs := append([]string(nil), e.dirs...)
	e.mu.RUnlock()
	// Rebuild the policy set from scratch so that (a) files load in filename
	// order - os.ReadDir is sorted - including a newly-added file, which must
	// slot into its numeric position rather than append to the end, and (b)
	// a policy whose file was deleted is dropped. Without this, a hot-added
	// NN-file could evaluate after higher-numbered files (letting a broad rate
	// rule mask a specific one), and removed files would linger.
	e.mu.Lock()
	e.policies = nil
	e.mu.Unlock()
	for _, d := range dirs {
		if err := e.LoadDir(d); err != nil {
			return err
		}
	}
	e.rebuild()
	e.logger.Info("policy engine reloaded", "rules", e.RuleCount())
	return nil
}

// SetDirs configures directories for watch/reload and loads them once.
func (e *Engine) SetDirs(dirs []string, watch bool) error {
	e.mu.Lock()
	e.dirs = append([]string(nil), dirs...)
	e.watch = watch
	e.mu.Unlock()
	return e.Reload()
}

// Watch starts hot-reload: filesystem notification with a 2s debounce and a
// 30s safety rescan. It blocks until Stop; run in a goroutine.
func (e *Engine) Watch(ctx context.Context) error {
	e.mu.RLock()
	dirs := append([]string(nil), e.dirs...)
	enabled := e.watch
	e.mu.RUnlock()
	if !enabled || len(dirs) == 0 {
		<-ctx.Done()
		return nil
	}

	w, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("policy: watcher: %w", err)
	}
	defer w.Close()
	for _, d := range dirs {
		_ = w.Add(d)
	}

	debounce := time.NewTimer(time.Hour)
	defer debounce.Stop()
	rescan := time.NewTicker(30 * time.Second)
	defer rescan.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-e.stopWatch:
			return nil
		case <-debounce.C:
			if err := e.Reload(); err != nil {
				e.logger.Error("policy hot reload failed", "err", err)
			}
		case <-rescan.C:
			if err := e.Reload(); err != nil {
				e.logger.Error("policy rescan failed", "err", err)
			}
		case ev, ok := <-w.Events:
			if !ok {
				return nil
			}
			switch ev.Op {
			case fsnotify.Create, fsnotify.Write, fsnotify.Remove, fsnotify.Rename:
				debounce.Reset(2 * time.Second)
			}
		}
	}
}

// Stop terminates the watcher loop.
func (e *Engine) Stop() {
	select {
	case <-e.stopWatch:
	default:
		close(e.stopWatch)
	}
}

// Evaluate runs the ordered rule set against ctx.
//
// Semantics:
//   - first matching rule with a deny/drop/reset/kill/freeze/quarantine action
//     decides the verdict (ALLOWED=false) and stops evaluation;
//   - allow-only rules annotate the event and continue;
//   - if nothing matches, spec.default_action decides (first non-empty among
//     loaded policies, default allow);
//   - rate rules: when the subject exceeded the quota, the rule enforces its
//     deny actions.
func (e *Engine) Evaluate(ctx *Context) Decision {
	e.mu.RLock()
	entries := e.entries
	def := "allow"
	for _, p := range e.policies {
		if p.Spec.DefaultAction != "" {
			def = p.Spec.DefaultAction
			break
		}
	}
	e.mu.RUnlock()

	if ctx.Now.IsZero() {
		ctx.Now = time.Now()
	}

	d := Decision{Allowed: strings.EqualFold(def, "allow"), Severity: events.SevInfo}
	if d.Allowed {
		d.Reason = "no rule matched (default allow)"
	} else {
		d.Reason = "no rule matched (default deny)"
	}

	key := subjectKey(ctx)
	for i := range entries {
		cr := &entries[i]
		r := &cr.rule
		if !r.IsEnabled() {
			continue
		}
		if !matchRule(cr, ctx) {
			continue
		}

		d.RuleIDs = append(d.RuleIDs, r.ID)
		d.RuleNames = append(d.RuleNames, r.Name)
		if s := events.ParseSeverity(r.Severity); s.Order() > d.Severity.Order() {
			d.Severity = s
		}

		// Rate-limited rule: the deny/alert actions apply ONLY when the
		// subject exceeds the window. Under the limit the rule does not
		// enforce - it's a throttle, not a blanket block - so we skip the
		// general denies(r) path below for rate rules.
		if r.Rate != nil {
			if e.rates.exceeded(key+"|"+r.ID, r.Rate.Events, mustWindow(r.Rate.Window), ctx.Now) {
				d.Allowed = false
				d.Reason = fmt.Sprintf("rate limit exceeded by rule %s", r.ID)
				d.Actions = append(d.Actions, denyActions(r)...)
				return d
			}
			// under the limit: record the match (for observability) but do not
			// enforce this rule; continue to the next rule.
			continue
		}

		if denies(r) {
			d.Allowed = false
			d.Reason = fmt.Sprintf("matched rule %s (%s)", r.ID, r.Name)
			d.Actions = append(d.Actions, denyActions(r)...)
			return d
		}
		// Explicit allow: first-match-wins, like a network firewall ACCEPT.
		// This is what makes a default-deny (zero-trust allowlist) policy work -
		// a matching allow rule PERMITS the query and stops evaluation.
		if allows(r) {
			d.Allowed = true
			d.Reason = fmt.Sprintf("allowed by rule %s (%s)", r.ID, r.Name)
			for _, a := range r.Actions {
				if pa := events.ParseAction(a); pa == events.ActAlert || pa == events.ActMask {
					d.Actions = append(d.Actions, pa)
				}
			}
			return d
		}
		for _, a := range r.Actions {
			if pa := events.ParseAction(a); pa == events.ActAlert || pa == events.ActMask {
				d.Actions = append(d.Actions, pa)
			}
		}
	}
	return d
}

func mustWindow(w string) time.Duration {
	d, err := parseWindow(w)
	if err != nil {
		return time.Minute
	}
	return d
}

// allows reports whether the rule carries an explicit allow action.
func allows(r *Rule) bool {
	for _, a := range r.Actions {
		if events.ParseAction(a) == events.ActAllow {
			return true
		}
	}
	return false
}

func denies(r *Rule) bool {
	for _, a := range r.Actions {
		switch events.ParseAction(a) {
		case events.ActDeny, events.ActDrop, events.ActReset, events.ActKill,
			events.ActFreeze, events.ActQuarantine:
			return true
		}
	}
	return false
}

func denyActions(r *Rule) []events.Action {
	var out []events.Action
	for _, a := range r.Actions {
		pa := events.ParseAction(a)
		if pa == events.ActAlert || deniesOne(pa) {
			out = append(out, pa)
		}
	}
	return out
}

func deniesOne(a events.Action) bool {
	switch a {
	case events.ActDeny, events.ActDrop, events.ActReset, events.ActKill,
		events.ActFreeze, events.ActQuarantine, events.ActRateLimit:
		return true
	}
	return false
}

func subjectKey(ctx *Context) string {
	return ctx.User + "@" + ctx.ClientIP
}

// matchIdentity reports whether the connection's Cilium identity matches any
// `identities` entry. An entry matches when it equals the numeric identity id,
// equals one of the identity's labels, or is a substring of a label (so
// "api-server" matches the label "k8s:app=api-server"). If the connection has
// no resolved identity (Cilium disabled or agent unaware of the IP), an
// identity-scoped rule does not match - fail closed for the rule's filter.
func matchIdentity(want []string, id string, labels []string) bool {
	if id == "" && len(labels) == 0 {
		return false
	}
	for _, w := range want {
		if w == "" {
			continue
		}
		if id != "" && strings.EqualFold(w, id) {
			return true
		}
		for _, lbl := range labels {
			if strings.EqualFold(w, lbl) || strings.Contains(strings.ToLower(lbl), strings.ToLower(w)) {
				return true
			}
		}
	}
	return false
}

func matchRule(cr *compiledRule, ctx *Context) bool {
	r := &cr.rule
	if len(r.Engines) > 0 && !containsFold(r.Engines, ctx.Engine) {
		return false
	}
	if len(r.Databases) > 0 && !containsFold(r.Databases, ctx.Database) {
		return false
	}
	if len(r.Users) > 0 && !containsFold(r.Users, ctx.User) {
		return false
	}
	if len(cr.cidrs) > 0 && !ipInAny(cr.cidrs, ctx.ClientIP) {
		return false
	}
	if len(r.Identities) > 0 && !matchIdentity(r.Identities, ctx.CiliumIdentity, ctx.CiliumLabels) {
		return false
	}
	if len(r.Tables) > 0 && !anyContainsFold(r.Tables, ctx.Tables) {
		return false
	}
	if len(r.Columns) > 0 && !anyContainsFold(r.Columns, ctx.Columns) {
		return false
	}
	if r.Query != nil {
		if !matchQuery(cr, ctx.SQL) {
			return false
		}
	}
	return true
}

func matchQuery(cr *compiledRule, sql string) bool {
	q := cr.rule.Query
	if len(sql) < q.MinLength {
		return false
	}
	if cr.re != nil && !cr.re.MatchString(sql) {
		return false
	}
	// Keywords are ANY-of (documented in rules.go): the rule matches if the SQL
	// contains AT LEAST ONE of the listed substrings. (Previously this required
	// ALL of them, so e.g. [into outfile, load_file] only matched text that had
	// both - a file-primitive rule that never fired.)
	if len(cr.keyws) > 0 {
		hay := sql
		if q.CaseInsensitive {
			hay = strings.ToLower(sql)
		}
		anyHit := false
		for _, k := range cr.keyws {
			if strings.Contains(hay, k) {
				anyHit = true
				break
			}
		}
		if !anyHit {
			return false
		}
	}
	// A query matcher with neither a pattern nor keywords matches nothing.
	return cr.re != nil || len(cr.keyws) > 0
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func anyContainsFold(list []string, vals []string) bool {
	for _, x := range list {
		for _, v := range vals {
			if strings.EqualFold(x, v) {
				return true
			}
		}
	}
	return false
}

func ipInAny(prefixes []netip.Prefix, ipStr string) bool {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		// The client IP is unknown (e.g. a query captured at the DB backend via
		// uprobe, where the socket peer isn't known at that point). A catch-all
		// prefix (0.0.0.0/0 or ::/0, i.e. Bits()==0) still matches "any client",
		// so rules and rate limits scoped to 0.0.0.0/0 apply to such queries.
		for _, p := range prefixes {
			if p.Bits() == 0 {
				return true
			}
		}
		return false
	}
	ip = ip.Unmap()
	for _, p := range prefixes {
		if p.Bits() == 0 || p.Contains(ip) {
			return true
		}
	}
	return false
}

// RuleCount returns the number of compiled rules.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.entries)
}

// Policies returns loaded policy metadata for status pages.
func (e *Engine) Policies() []PolicyInfo {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]PolicyInfo, 0, len(e.policies))
	for _, p := range e.policies {
		n := 0
		for _, r := range p.Spec.Rules {
			if r.IsEnabled() {
				n++
			}
		}
		out = append(out, PolicyInfo{
			Name:        p.Metadata.Name,
			Description: p.Metadata.Description,
			Rules:       n,
			Default:     p.Spec.DefaultAction,
		})
	}
	return out
}

// PolicyInfo summarises one loaded policy document.
type PolicyInfo struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Rules       int    `json:"rules"`
	Default     string `json:"default_action"`
}

// ---- sliding-window rate limiter ----

type rateLimiter struct {
	mu      sync.Mutex
	windows map[string][]time.Time
}

func newRateLimiter() *rateLimiter {
	return &rateLimiter{windows: make(map[string][]time.Time)}
}

func (r *rateLimiter) exceeded(key string, max int, window time.Duration, now time.Time) bool {
	if max <= 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	stamps := r.windows[key]
	// prune
	cut := now.Add(-window)
	keep := stamps[:0]
	for _, t := range stamps {
		if t.After(cut) {
			keep = append(keep, t)
		}
	}
	if len(keep) >= max {
		r.windows[key] = keep
		return true
	}
	r.windows[key] = append(keep, now)
	return false
}

// Prune removes empty windows (call periodically to bound memory).
func (r *rateLimiter) Prune(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, stamps := range r.windows {
		if len(stamps) == 0 {
			delete(r.windows, k)
		}
	}
}
