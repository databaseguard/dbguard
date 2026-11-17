// Package policy implements DBGuard's configurable firewall: YAML policy
// documents are compiled into matchers evaluated per query/event.
//
// This file (rules.go) defines the document schema; engine.go holds the
// evaluation engine, rate limiter and hot reload.
package policy

// Policy is the root of a policy YAML document.
type Policy struct {
	APIVersion string   `yaml:"api_version"`
	Kind       string   `yaml:"kind"`
	Metadata   Metadata `yaml:"metadata"`
	Spec       Spec     `yaml:"spec"`
}

// Metadata identifies a policy document.
type Metadata struct {
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Labels      map[string]string `yaml:"labels"`
}

// Spec is the rule set plus the default verdict.
type Spec struct {
	// DefaultAction is applied when no rule matches: allow|deny.
	DefaultAction string `yaml:"default_action"`
	Rules         []Rule `yaml:"rules"`
}

// Rule is one firewall/policy rule.
type Rule struct {
	ID          string `yaml:"id"`
	Name        string `yaml:"name"`
	Description string `yaml:"description"`
	// Enabled is a pointer so YAML "enabled: false" works while the
	// zero value defaults to enabled.
	Enabled *bool `yaml:"enabled"`

	Severity string `yaml:"severity"` // info|low|medium|high|critical

	// Subject matchers (empty = match all).
	Engines    []string `yaml:"engines"` // postgres|mysql|sqlite
	Databases  []string `yaml:"databases"`
	Users      []string `yaml:"users"`
	Clients    []string `yaml:"clients"`    // CIDRs or IPs
	Identities []string `yaml:"identities"` // Cilium security identity: id (e.g. "12345") or label (e.g. "k8s:app=api-server" / "api-server")

	// Object matchers.
	Tables  []string `yaml:"tables"`
	Columns []string `yaml:"columns"`

	// Content matcher on SQL text.
	Query *QueryMatcher `yaml:"query"`

	// Rate limiting: allow at most Events per Window per subject key.
	Rate *RateRule `yaml:"rate"`

	// Actions decided when the rule matches. Denying actions stop
	// evaluation and enforce; alerting actions annotate and continue.
	Actions []string `yaml:"actions"`
}

// IsEnabled reports whether the rule is active (default true).
func (r *Rule) IsEnabled() bool {
	return r.Enabled == nil || *r.Enabled
}

// QueryMatcher matches SQL text content.
type QueryMatcher struct {
	Pattern         string   `yaml:"pattern"`  // Go regexp
	Keywords        []string `yaml:"keywords"` // ANY-of substrings
	CaseInsensitive bool     `yaml:"case_insensitive"`
	MinLength       int      `yaml:"min_length"`
}

// RateRule throttles matched subjects.
type RateRule struct {
	Events int    `yaml:"events"` // max events...
	Window string `yaml:"window"` // ...per window, e.g. "10s", "1m", "1h"
}
