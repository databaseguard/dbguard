// Package config defines DBGuard's YAML configuration schema, defaults,
// validation and loading.
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config is the root configuration document (configs/dbguard.yaml).
type Config struct {
	General  GeneralConfig  `yaml:"general"`
	Log      LogConfig      `yaml:"logging"`
	EBPF     EBPFConfig     `yaml:"ebpf"`
	Policies PoliciesConfig `yaml:"policies"`
	Audit    AuditConfig    `yaml:"audit"`
	PII      PIIConfig      `yaml:"pii"`
	SQLi     SQLiConfig     `yaml:"sqli"`
	Anomaly  AnomalyConfig  `yaml:"anomaly"`
	Exfil    ExfilConfig    `yaml:"exfil"`
	RIDS     RIDSConfig     `yaml:"rids"`
	Lineage  LineageConfig  `yaml:"lineage"`
	Tenant   TenantConfig   `yaml:"tenant"`
	Identity IdentityConfig `yaml:"identity"`
	API      APIConfig      `yaml:"api"`
	Alerts   AlertsConfig   `yaml:"alerts"`
	Metrics  MetricsConfig  `yaml:"metrics"`
	Proxy    ProxyConfig    `yaml:"proxy"`   // single listener (back-compat)
	Proxies  []ProxyConfig  `yaml:"proxies"` // multiple listeners (preferred)
}

// EffectiveProxies returns the set of inline proxy listeners to start. When the
// plural `proxies:` list is present it wins; otherwise the singular `proxy:`
// block is used (back-compat). Only enabled, fully-specified entries are kept.
func (c *Config) EffectiveProxies() []ProxyConfig {
	var out []ProxyConfig
	src := c.Proxies
	if len(src) == 0 {
		src = []ProxyConfig{c.Proxy}
	}
	for _, p := range src {
		if !p.Enabled || p.Listen == "" || p.Upstream == "" {
			continue
		}
		if p.Engine == "" {
			p.Engine = "postgres"
		}
		out = append(out, p)
	}
	return out
}

// ProxyConfig configures the optional synchronous inline enforcement proxy.
// When enabled, clients connect to the proxy's listen address instead of the
// database directly; denied queries are rejected before reaching the DB, so no
// rows ever return for a blocked statement (closes the uprobe fast-query race).
type ProxyConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Listen   string `yaml:"listen"`   // e.g. 127.0.0.1:6432
	Upstream string `yaml:"upstream"` // real DB, e.g. 127.0.0.1:5432
	Engine   string `yaml:"engine"`   // "postgres"
}

// GeneralConfig holds instance-wide settings.
type GeneralConfig struct {
	Name    string `yaml:"name"`
	DataDir string `yaml:"data_dir"`
	PidFile string `yaml:"pid_file"`
}

// LogConfig configures logging.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// PortsConfig configures the well-known DB ports used by wire-level hooks.
type PortsConfig struct {
	Postgres int `yaml:"postgres"`
	MySQL    int `yaml:"mysql"`
	SQLite   int `yaml:"sqlite_port"` // only relevant for TCP front-ends (e.g. litestream/steampipe)
}

// AttachConfig lists symbols DBGuard uprobes attach to. Defaults cover
// stock PostgreSQL/MySQL/SQLite builds; extend for custom builds.
type AttachConfig struct {
	PostgresSymbols []string `yaml:"postgres_symbols"`
	MySQLSymbols    []string `yaml:"mysql_symbols"`
	SQLiteSymbols   []string `yaml:"sqlite_symbols"`
	OpenSSLSymbols  []string `yaml:"openssl_symbols"`
}

// EBPFConfig controls kernel program loading and attachment.
type EBPFConfig struct {
	Enabled       bool         `yaml:"enabled"`
	ObjectDir     string       `yaml:"object_dir"`
	PinPath       string       `yaml:"pin_path"`
	RingbufPages  int          `yaml:"ringbuf_pages"`
	Ports         PortsConfig  `yaml:"ports"`
	DropEnabled   bool         `yaml:"drop_enabled"`
	LSMEnabled    bool         `yaml:"lsm_enabled"`
	XDPInterfaces []string     `yaml:"xdp_interfaces"`
	Attach        AttachConfig `yaml:"attach"`
}

// PoliciesConfig points at policy directories with optional hot reload.
type PoliciesConfig struct {
	Dirs  []string `yaml:"dirs"`
	Watch bool     `yaml:"watch"`
}

// AuditConfig configures the audit store.
type AuditConfig struct {
	Enabled          bool   `yaml:"enabled"`
	Store            string `yaml:"store"` // jsonl
	Dir              string `yaml:"dir"`
	MaxSizeMB        int    `yaml:"max_size_mb"`
	MaxFiles         int    `yaml:"max_files"`
	FlushIntervalSec int    `yaml:"flush_interval_sec"`
	RedactPII        bool   `yaml:"redact_pii"`
}

// PIIConfig configures PII detection.
type PIIConfig struct {
	Enabled          bool     `yaml:"enabled"`
	Patterns         []string `yaml:"patterns"`          // empty = all built-ins
	DisabledPatterns []string `yaml:"disabled_patterns"` // exclude by name
	EntropyThreshold float64  `yaml:"entropy_threshold"` // Shannon bits/char
	MaxScanLen       int      `yaml:"max_scan_len"`      // bytes of SQL to scan
	Redact           bool     `yaml:"redact"`            // mask in logs/audit
	AlertOnly        bool     `yaml:"alert_only"`        // never deny, only alert
}

// SQLiConfig configures the SQL injection firewall.
type SQLiConfig struct {
	Enabled             bool    `yaml:"enabled"`
	Sensitivity         string  `yaml:"sensitivity"`          // low|medium|high
	ConfidenceThreshold float64 `yaml:"confidence_threshold"` // deny above this
	InKernelDrop        bool    `yaml:"in_kernel_drop"`       // let eBPF drop pre-parser
	MaxSQLLen           int     `yaml:"max_sql_len"`
}

// AnomalyConfig configures connection-pool & behavioural anomaly detection.
type AnomalyConfig struct {
	Enabled             bool    `yaml:"enabled"`
	WindowSec           int     `yaml:"window_sec"`
	QueryRateThreshold  float64 `yaml:"query_rate_threshold"`  // queries/sec per client
	ConnSpikeThreshold  int     `yaml:"conn_spike_threshold"`  // new conns per window
	AdminConcurrentMax  int     `yaml:"admin_concurrent_max"`  // concurrent superuser logins
	FailedAuthThreshold int     `yaml:"failed_auth_threshold"` // consecutive failures
	BaselineWindowMin   int     `yaml:"baseline_window_min"`
}

// ExfilConfig configures the bulk-dump breaker.
type ExfilConfig struct {
	Enabled           bool   `yaml:"enabled"`
	WindowMS          int    `yaml:"window_ms"`
	MaxBytesPerWindow uint64 `yaml:"max_bytes_per_window"`
	MaxRateKbps       uint64 `yaml:"max_rate_kbps"`
	QuarantineSec     int    `yaml:"quarantine_sec"`
	ResetEnabled      bool   `yaml:"reset_enabled"` // kernel RST/drop for offender
}

// FIMConfig configures file-integrity monitoring of DB data directories.
type FIMConfig struct {
	Enabled     bool     `yaml:"enabled"`
	Dirs        []string `yaml:"dirs"`
	IntervalSec int      `yaml:"interval_sec"`
}

// RIDSConfig configures the runtime intrusion detection system.
type RIDSConfig struct {
	Enabled         bool      `yaml:"enabled"`
	AlertOnly       bool      `yaml:"alert_only"`
	BlockedBinaries []string  `yaml:"blocked_binaries"` // e.g. /bin/sh, /bin/bash, wget, nc
	ProtectedPaths  []string  `yaml:"protected_paths"`  // data dir prefixes
	MaxPathLen      int       `yaml:"max_path_len"`
	FIM             FIMConfig `yaml:"fim"`
}

// RuntimeProbe describes an uprobe installed into an application runtime to
// capture HTTP route context (feature 8: dual-sided context matcher).
type RuntimeProbe struct {
	Binary string `yaml:"binary"` // binary name or path fragment
	Symbol string `yaml:"symbol"` // symbol to probe (ELF symbol)
	Kind   string `yaml:"kind"`   // go|node|jvm|openssl|generic
}

// LineageConfig configures app-to-DB lineage verification.
type LineageConfig struct {
	Enabled              bool           `yaml:"enabled"`
	CorrelationWindowSec int            `yaml:"correlation_window_sec"`
	TeardownEnabled      bool           `yaml:"teardown_enabled"`
	RuntimeProbes        []RuntimeProbe `yaml:"runtime_probes"`
	AllowedRouteMismatch int            `yaml:"allowed_route_mismatch"`
}

// TenantDef declares one tenant for multi-tenant isolation.
type TenantDef struct {
	ID           string   `yaml:"id"`
	Cgroups      []string `yaml:"cgroups"`       // cgroup path fragments
	AllowedPaths []string `yaml:"allowed_paths"` // filesystem prefixes
	AllowedCIDRs []string `yaml:"allowed_cidrs"` // network sources
}

// TenantConfig configures feature 9 (multi-tenant isolation guard).
type TenantConfig struct {
	Enabled   bool        `yaml:"enabled"`
	AlertOnly bool        `yaml:"alert_only"`
	Tenants   []TenantDef `yaml:"tenants"`
}

// IdentityConfig controls workload identity resolution.
type IdentityConfig struct {
	Enabled       bool   `yaml:"enabled"`
	ContainerHint string `yaml:"container_hint"` // docker|containerd|crio|auto
	CiliumEnabled bool   `yaml:"cilium_enabled"`
	CiliumAPIURL  string `yaml:"cilium_api_url"`
}

// APIConfig configures the admin REST API.
type APIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	TLSCert string `yaml:"tls_cert"`
	TLSKey  string `yaml:"tls_key"`
	Token   string `yaml:"token"` // bearer token; empty = no auth (loopback only)
}

// SinkConfig is one alert sink.
type SinkConfig struct {
	Type     string `yaml:"type"` // webhook|slack|syslog|file
	URL      string `yaml:"url"`
	Timeout  int    `yaml:"timeout_sec"`
	Host     string `yaml:"host"` // syslog
	Port     int    `yaml:"port"` // syslog
	Facility string `yaml:"facility"`
	File     string `yaml:"file"` // file sink
	MinSev   string `yaml:"min_severity"`
}

// AlertsConfig configures alert routing.
type AlertsConfig struct {
	MinSeverity    string       `yaml:"min_severity"`
	DedupWindowSec int          `yaml:"dedup_window_sec"`
	Sinks          []SinkConfig `yaml:"sinks"`
}

// MetricsConfig configures Prometheus telemetry.
type MetricsConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
	Path    string `yaml:"path"`
}

// Load reads, defaults and validates a configuration file.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(raw, cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// LoadString parses configuration from an in-memory YAML string (tests/CLI).
func LoadString(s string) (*Config, error) {
	cfg := &Config{}
	if err := yaml.Unmarshal([]byte(s), cfg); err != nil {
		return nil, fmt.Errorf("config: parse: %w", err)
	}
	cfg.ApplyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks invariants and returns the first error found.
func (c *Config) Validate() error {
	if c.General.Name == "" {
		return fmt.Errorf("config: general.name is required")
	}
	switch strings.ToLower(c.SQLi.Sensitivity) {
	case "low", "medium", "high":
	default:
		return fmt.Errorf("config: sqli.sensitivity must be low|medium|high")
	}
	if c.EBPF.Enabled {
		if c.EBPF.Ports.Postgres <= 0 || c.EBPF.Ports.Postgres > 65535 {
			return fmt.Errorf("config: ebpf.ports.postgres out of range")
		}
		if c.EBPF.Ports.MySQL <= 0 || c.EBPF.Ports.MySQL > 65535 {
			return fmt.Errorf("config: ebpf.ports.mysql out of range")
		}
	}
	if c.Exfil.Enabled && c.Exfil.WindowMS <= 0 {
		return fmt.Errorf("config: exfil.window_ms must be > 0 when enabled")
	}
	for i, s := range c.Alerts.Sinks {
		switch s.Type {
		case "webhook", "slack":
			if s.URL == "" {
				return fmt.Errorf("config: alerts.sinks[%d].url is required for %s", i, s.Type)
			}
		case "syslog":
			if s.Host == "" {
				return fmt.Errorf("config: alerts.sinks[%d].host is required for syslog", i)
			}
		case "file":
			if s.File == "" {
				return fmt.Errorf("config: alerts.sinks[%d].file is required for file sink", i)
			}
		default:
			return fmt.Errorf("config: alerts.sinks[%d].type must be webhook|slack|syslog|file", i)
		}
	}
	for i, t := range c.Tenant.Tenants {
		if t.ID == "" {
			return fmt.Errorf("config: tenant.tenants[%d].id is required", i)
		}
	}
	return nil
}

// envOverride applies DBGUARD_<SECTION>_<KEY> style env overrides for a few
// hot keys (useful in containers).
func (c *Config) envOverride() {
	if v := os.Getenv("DBGUARD_API_LISTEN"); v != "" {
		c.API.Listen = v
	}
	if v := os.Getenv("DBGUARD_LOG_LEVEL"); v != "" {
		c.Log.Level = v
	}
	if v := os.Getenv("DBGUARD_EBPF_OBJECT_DIR"); v != "" {
		c.EBPF.ObjectDir = v
	}
	if v := os.Getenv("DBGUARD_EBPF_DROP"); v != "" {
		c.EBPF.DropEnabled, _ = strconv.ParseBool(v)
	}
}
