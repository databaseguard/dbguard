package config

// DefaultPorts mirrors common database defaults.
const (
	DefaultPostgresPort = 5432
	DefaultMySQLPort    = 3306
)

// ApplyDefaults fills every unset field with an operational default so the
// zero-value config is safe after Load/LoadString.
func (c *Config) ApplyDefaults() {
	c.envOverride()

	if c.General.Name == "" {
		c.General.Name = "dbguard"
	}
	if c.General.DataDir == "" {
		c.General.DataDir = "/var/lib/dbguard"
	}
	if c.General.PidFile == "" {
		c.General.PidFile = "/run/dbguard.pid"
	}
	if c.Log.Level == "" {
		c.Log.Level = "info"
	}
	if c.Log.Format == "" {
		c.Log.Format = "text"
	}

	if c.EBPF.ObjectDir == "" {
		c.EBPF.ObjectDir = "/var/lib/dbguard/bpf"
	}
	if c.EBPF.PinPath == "" {
		c.EBPF.PinPath = "/sys/fs/bpf/dbguard"
	}
	if c.EBPF.RingbufPages == 0 {
		c.EBPF.RingbufPages = 256 // 4KB pages => 1MB ring buffer
	}
	if c.EBPF.Ports.Postgres == 0 {
		c.EBPF.Ports.Postgres = DefaultPostgresPort
	}
	if c.EBPF.Ports.MySQL == 0 {
		c.EBPF.Ports.MySQL = DefaultMySQLPort
	}
	if len(c.EBPF.Attach.PostgresSymbols) == 0 {
		c.EBPF.Attach.PostgresSymbols = []string{"exec_simple_query", "pg_parse_query"}
	}
	if len(c.EBPF.Attach.MySQLSymbols) == 0 {
		// dispatch_command is usually static/hidden; the watcher also tries
		// the common C++ mangled names used by shipped builds.
		c.EBPF.Attach.MySQLSymbols = []string{
			"_Z16dispatch_command19enum_server_commandP3THDPcj",
			"_Z16dispatch_command19enum_server_commandP3THDPcji",
			"dispatch_command",
			"mysql_parse",
		}
	}
	if len(c.EBPF.Attach.SQLiteSymbols) == 0 {
		c.EBPF.Attach.SQLiteSymbols = []string{"sqlite3_exec", "sqlite3_prepare_v2", "sqlite3_prepare_v3"}
	}
	if len(c.EBPF.Attach.OpenSSLSymbols) == 0 {
		c.EBPF.Attach.OpenSSLSymbols = []string{"SSL_write", "SSL_read", "SSL_new"}
	}

	if len(c.Policies.Dirs) == 0 {
		c.Policies.Dirs = []string{"/etc/dbguard/policies"}
	}

	if !c.Audit.Enabled && c.Audit.Store == "" {
		// auditing defaults ON: a security tool without an audit trail is moot
		c.Audit.Enabled = true
		c.Audit.Store = "jsonl"
	}
	if c.Audit.Store == "" {
		c.Audit.Store = "jsonl"
	}
	if c.Audit.Dir == "" {
		c.Audit.Dir = c.General.DataDir + "/audit"
	}
	if c.Audit.MaxSizeMB == 0 {
		c.Audit.MaxSizeMB = 100
	}
	if c.Audit.MaxFiles == 0 {
		c.Audit.MaxFiles = 30
	}
	if c.Audit.FlushIntervalSec == 0 {
		c.Audit.FlushIntervalSec = 2
	}

	if c.PII.EntropyThreshold == 0 {
		c.PII.EntropyThreshold = 4.5
	}
	if c.PII.MaxScanLen == 0 {
		c.PII.MaxScanLen = 8192
	}

	if c.SQLi.Sensitivity == "" {
		c.SQLi.Sensitivity = "medium"
	}
	if c.SQLi.ConfidenceThreshold == 0 {
		c.SQLi.ConfidenceThreshold = 0.72
	}
	if c.SQLi.MaxSQLLen == 0 {
		c.SQLi.MaxSQLLen = 16384
	}

	if c.Anomaly.WindowSec == 0 {
		c.Anomaly.WindowSec = 60
	}
	if c.Anomaly.QueryRateThreshold == 0 {
		c.Anomaly.QueryRateThreshold = 80
	}
	if c.Anomaly.ConnSpikeThreshold == 0 {
		c.Anomaly.ConnSpikeThreshold = 40
	}
	if c.Anomaly.AdminConcurrentMax == 0 {
		c.Anomaly.AdminConcurrentMax = 3
	}
	if c.Anomaly.FailedAuthThreshold == 0 {
		c.Anomaly.FailedAuthThreshold = 10
	}
	if c.Anomaly.BaselineWindowMin == 0 {
		c.Anomaly.BaselineWindowMin = 30
	}

	if c.Exfil.WindowMS == 0 {
		c.Exfil.WindowMS = 100
	}
	if c.Exfil.MaxBytesPerWindow == 0 {
		c.Exfil.MaxBytesPerWindow = 8 << 20 // 8 MiB per 100ms burst
	}
	if c.Exfil.MaxRateKbps == 0 {
		c.Exfil.MaxRateKbps = 200 * 1024 // 200 MB/s sustained
	}
	if c.Exfil.QuarantineSec == 0 {
		c.Exfil.QuarantineSec = 30
	}

	if c.RIDS.MaxPathLen == 0 {
		c.RIDS.MaxPathLen = 256
	}
	if c.RIDS.FIM.IntervalSec == 0 {
		c.RIDS.FIM.IntervalSec = 300
	}
	if len(c.RIDS.BlockedBinaries) == 0 {
		c.RIDS.BlockedBinaries = []string{"/bin/sh", "/bin/bash", "/bin/dash", "/usr/bin/wget", "/usr/bin/curl", "/usr/bin/nc", "/usr/bin/ncat", "/usr/bin/python3", "/usr/bin/perl"}
	}

	if c.Lineage.CorrelationWindowSec == 0 {
		c.Lineage.CorrelationWindowSec = 30
	}
	if c.Lineage.AllowedRouteMismatch == 0 {
		c.Lineage.AllowedRouteMismatch = 3
	}

	if c.API.Listen == "" {
		c.API.Listen = "127.0.0.1:9700"
	}

	if c.Alerts.MinSeverity == "" {
		c.Alerts.MinSeverity = "medium"
	}
	if c.Alerts.DedupWindowSec == 0 {
		c.Alerts.DedupWindowSec = 60
	}

	if c.Metrics.Listen == "" {
		c.Metrics.Listen = "127.0.0.1:9701"
	}
	if c.Metrics.Path == "" {
		c.Metrics.Path = "/metrics"
	}

	if c.Identity.ContainerHint == "" {
		c.Identity.ContainerHint = "auto"
	}
}
