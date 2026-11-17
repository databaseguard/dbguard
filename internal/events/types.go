// Package events defines the event model that flows through DBGuard's
// pipeline: kernel ring-buffer records are decoded into Event, enriched,
// matched against policy, inspected by detectors and finally dispatched to
// alert sinks and the audit store.
package events

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// Severity classifies how urgently an event needs human attention.
type Severity string

const (
	SevInfo     Severity = "info"
	SevLow      Severity = "low"
	SevMedium   Severity = "medium"
	SevHigh     Severity = "high"
	SevCritical Severity = "critical"
)

// Order returns the numeric weight of a severity (higher = more severe).
func (s Severity) Order() int {
	switch s {
	case SevCritical:
		return 4
	case SevHigh:
		return 3
	case SevMedium:
		return 2
	case SevLow:
		return 1
	default:
		return 0
	}
}

// ParseSeverity maps an arbitrary string onto a Severity (default info).
func ParseSeverity(s string) Severity {
	switch s {
	case "critical", "crit":
		return SevCritical
	case "high":
		return SevHigh
	case "medium", "warn", "warning":
		return SevMedium
	case "low":
		return SevLow
	default:
		return SevInfo
	}
}

// Action is a decision the system takes (or requests) for an event.
type Action string

const (
	ActAllow      Action = "allow"
	ActAlert      Action = "alert"
	ActDeny       Action = "deny"
	ActDrop       Action = "drop"
	ActReset      Action = "reset"  // inject TCP RST / terminate connection
	ActMask       Action = "mask"   // redact PII from logs/exports
	ActKill       Action = "kill"   // SIGKILL offending process
	ActFreeze     Action = "freeze" // cgroup v2 freeze
	ActQuarantine Action = "quarantine"
	ActRateLimit  Action = "rate_limit"
)

// AllActions lists every action for validation purposes.
var AllActions = []Action{ActAllow, ActAlert, ActDeny, ActDrop, ActReset,
	ActMask, ActKill, ActFreeze, ActQuarantine, ActRateLimit}

// IsValidAction reports whether s is a known action.
func IsValidAction(s string) bool {
	for _, a := range AllActions {
		if string(a) == s {
			return true
		}
	}
	return false
}

// ParseAction maps an arbitrary string onto an Action (default alert).
func ParseAction(s string) Action {
	for _, a := range AllActions {
		if string(a) == s {
			return a
		}
	}
	return ActAlert
}

// EventType is the pipeline-level classification of an event.
type EventType string

const (
	EvQueryAudit     EventType = "query.audit"     // SQL statement observed
	EvPIIHit         EventType = "pii.detection"   // PII found in query/result
	EvSQLi           EventType = "sqli.attempt"    // SQL injection attempt
	EvPolicyDecision EventType = "policy.decision" // firewall rule matched
	EvConnAnomaly    EventType = "connection.anomaly"
	EvAuthAnomaly    EventType = "auth.anomaly"
	EvExfil          EventType = "exfil.burst" // bulk dump / exfiltration
	EvExecve         EventType = "rids.execve" // shell/tool exec on DB host
	EvFileAccess     EventType = "rids.file_access"
	EvIntegrity      EventType = "rids.integrity"   // FIM hash change
	EvLineage        EventType = "lineage.mismatch" // route↔query mismatch
	EvTenant         EventType = "tenant.violation"
	EvConnOpen       EventType = "conn.open"
	EvConnClose      EventType = "conn.close"
	EvTLSSession     EventType = "tls.session"
)

// Finding is a structured detection result attached to an event.
type Finding struct {
	Kind       string   `json:"kind"`               // e.g. "credit_card", "sqli.tautology"
	Detail     string   `json:"detail"`             // human explanation
	Confidence float64  `json:"confidence"`         // 0.0 - 1.0
	Severity   Severity `json:"severity,omitempty"` // per-finding severity (optional)
	Snippet    string   `json:"snippet,omitempty"`  // (redacted) evidence
	Start      int      `json:"start,omitempty"`    // byte offset in SQL/text
	End        int      `json:"end,omitempty"`
}

// SessionKey builds the canonical join key used across modules
// (lineage, exfil, anomaly) for a TCP flow.
func SessionKey(clientIP string, clientPort uint16, serverPort uint16) string {
	return clientIP + ":" + itoa(int(clientPort)) + ">" + itoa(int(serverPort))
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

// Event is the single canonical event structure of DBGuard.
type Event struct {
	ID       string    `json:"id"`
	Type     EventType `json:"type"`
	Time     time.Time `json:"time"`
	Severity Severity  `json:"severity"`
	Message  string    `json:"message,omitempty"`
	RuleID   string    `json:"rule_id,omitempty"`
	RuleName string    `json:"rule_name,omitempty"`
	Actions  []Action  `json:"actions,omitempty"` // decided actions
	Allowed  bool      `json:"allowed"`           // policy verdict
	Source   string    `json:"source,omitempty"`  // module that produced it

	// Process / kernel context
	PID      uint32 `json:"pid,omitempty"`
	TID      uint32 `json:"tid,omitempty"`
	UID      uint32 `json:"uid,omitempty"`
	CgroupID uint64 `json:"cgroup_id,omitempty"`
	Binary   string `json:"binary,omitempty"` // comm of the DB process

	// Network context
	SessionID  uint64 `json:"session_id,omitempty"` // socket cookie
	ClientIP   string `json:"client_ip,omitempty"`
	ClientPort uint16 `json:"client_port,omitempty"`
	ServerIP   string `json:"server_ip,omitempty"`
	ServerPort uint16 `json:"server_port,omitempty"`

	// Database context
	Engine   string   `json:"engine,omitempty"` // postgres|mysql|sqlite|unknown
	User     string   `json:"user,omitempty"`
	Database string   `json:"database,omitempty"`
	SQL      string   `json:"sql,omitempty"`
	SQLLen   int      `json:"sql_len,omitempty"`
	Tables   []string `json:"tables,omitempty"`
	Columns  []string `json:"columns,omitempty"`

	// Workload identity
	ContainerID  string            `json:"container_id,omitempty"`
	PodName      string            `json:"pod_name,omitempty"`
	Namespace    string            `json:"namespace,omitempty"`
	CiliumID     string            `json:"cilium_identity,omitempty"` // Cilium security-identity id for ClientIP
	CiliumLabels []string          `json:"cilium_labels,omitempty"`   // the identity's labels, e.g. "k8s:app=api-server"
	Labels       map[string]string `json:"labels,omitempty"`

	// Lineage
	Route  string `json:"route,omitempty"`   // HTTP route / operation tag
	AppPID uint32 `json:"app_pid,omitempty"` // originating app process

	// Detections
	Findings []Finding `json:"findings,omitempty"`

	// Free-form module metadata
	Meta map[string]string `json:"meta,omitempty"`
}

// NewID returns a random 16-hex-char event id.
func NewID() string {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b[:])
}

// AddFinding appends a finding to the event.
func (e *Event) AddFinding(f Finding) {
	e.Findings = append(e.Findings, f)
}

// HasAction reports whether action a is already decided for this event.
func (e *Event) HasAction(a Action) bool {
	for _, x := range e.Actions {
		if x == a {
			return true
		}
	}
	return false
}

// AddAction adds an action if not present.
func (e *Event) AddAction(a Action) {
	if e.HasAction(a) {
		return
	}
	e.Actions = append(e.Actions, a)
}

// MetaGet returns a metadata value.
func (e *Event) MetaGet(k string) string {
	if e.Meta == nil {
		return ""
	}
	return e.Meta[k]
}

// MetaSet stores a metadata value.
func (e *Event) MetaSet(k, v string) {
	if e.Meta == nil {
		e.Meta = make(map[string]string, 4)
	}
	e.Meta[k] = v
}

// Clone returns a shallow copy safe for fan-out mutation of top-level fields.
func (e *Event) Clone() *Event {
	c := *e
	return &c
}
