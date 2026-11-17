// Package ebpf contains the Go-side of the kernel interface: wire-struct
// mirrors of bpf/include/dbguard/common.h, ring-buffer decoders, object
// loading and attachment management.
//
// types.go mirrors MUST stay in sync with common.h (packed layouts).
package ebpf

// Event type codes - mirror of DBG_EVT_* in common.h.
const (
	EvtQuery   uint32 = 1
	EvtAlert   uint32 = 2
	EvtFlow    uint32 = 3
	EvtExfil   uint32 = 4
	EvtExec    uint32 = 5
	EvtFile    uint32 = 6
	EvtLineage uint32 = 7
	EvtTenant  uint32 = 8
	EvtTLS     uint32 = 9
	EvtConn    uint32 = 10
)

// Engine codes - mirror of DBG_ENG_*.
const (
	EngUnknown  uint32 = 0
	EngPostgres uint32 = 1
	EngMySQL    uint32 = 2
	EngSQLite   uint32 = 3
)

// Action codes - mirror of DBG_ACT_*.
const (
	ActNone       uint32 = 0
	ActAlert      uint32 = 1
	ActDrop       uint32 = 2
	ActReset      uint32 = 3
	ActQuarantine uint32 = 4
	ActKill       uint32 = 5
	ActAllow      uint32 = 6
)

// Query pre-scan flags - mirror of DBG_QF_*.
const (
	QFPIIDigits  uint64 = 1 << 0
	QFLuhnHit    uint64 = 1 << 1
	QFSSNLike    uint64 = 1 << 2
	QFSecretLike uint64 = 1 << 3
	QFDDL        uint64 = 1 << 4
	QFBulkSelect uint64 = 1 << 5
	QFSQLIHint   uint64 = 1 << 6
)

// Alert event codes - mirror of DBG_ALC_*.
const (
	AlcSQLi      uint32 = 1
	AlcConnSpike uint32 = 2
	AlcAuthFail  uint32 = 3
	AlcTenant    uint32 = 4
	AlcPII       uint32 = 5
	AlcExfil     uint32 = 6
	AlcRIDSExec  uint32 = 7
	AlcRIDSFile  uint32 = 8
)

// Limits - mirror of DBG_MAX_*.
const (
	MaxSQL   = 512
	MaxMsg   = 256
	MaxPath  = 256
	MaxArg   = 256
	MaxComm  = 16
	MaxRoute = 128
	MaxSNI   = 64
)

// DbgHdr mirrors struct dbg_hdr (64 bytes, packed).
type DbgHdr struct {
	Type     uint32
	Action   uint32
	PID      uint32
	TID      uint32
	UID      uint32
	Severity uint32
	RuleID   uint32
	Engine   uint32
	Cgroup   uint64
	TsNS     uint64
	Session  uint64
	DataLen  uint32
	Pad      uint32
}

// QueryEvent mirrors struct dbg_query_event.
type QueryEvent struct {
	Hdr    DbgHdr
	SQL    [MaxSQL]byte
	Comm   [MaxComm]byte
	SQLLen uint32
	Family uint32
	Flags  uint64
	SAddr  [16]byte
	DAddr  [16]byte
	Sport  uint16
	DPort  uint16
	Pad2   uint32
}

// AlertEvent mirrors struct dbg_alert_event.
type AlertEvent struct {
	Hdr  DbgHdr
	Msg  [MaxMsg]byte
	Comm [MaxComm]byte
	Code uint32
	Pad  uint32
}

// FlowEvent mirrors struct dbg_flow_event.
type FlowEvent struct {
	Hdr     DbgHdr
	SAddr   [16]byte
	DAddr   [16]byte
	Sport   uint16
	DPort   uint16
	Proto   uint8
	Event   uint8
	Pad2    uint16
	Bytes   uint64
	Packets uint64
}

// ExfilEvent mirrors struct dbg_exfil_event.
type ExfilEvent struct {
	Hdr         DbgHdr
	BytesWindow uint64
	BytesTotal  uint64
	WindowMS    uint32
	RateKbps    uint32
	Verdict     uint8
	Pad         [3]byte
	SAddr       [16]byte
	DAddr       [16]byte
	Sport       uint16
	DPort       uint16
	Pad2        uint16
}

// ExecEvent mirrors struct dbg_exec_event.
type ExecEvent struct {
	Hdr     DbgHdr
	Path    [MaxPath]byte
	Argv    [MaxArg]byte
	Comm    [MaxComm]byte
	ArgC    int32
	Verdict uint32
	Pad     uint32
}

// FileEvent mirrors struct dbg_file_event.
type FileEvent struct {
	Hdr      DbgHdr
	Path     [MaxPath]byte
	Comm     [MaxComm]byte
	Flags    uint32
	Verdict  uint32
	TenantID uint32
	Pad      uint32
}

// LineageEvent mirrors struct dbg_lineage_event.
type LineageEvent struct {
	Hdr        DbgHdr
	Route      [MaxRoute]byte
	SockCookie uint64
	AppPID     uint32
	Flags      uint32
	Pad        uint32
}

// TenantEvent mirrors struct dbg_tenant_event.
type TenantEvent struct {
	Hdr         DbgHdr
	Path        [MaxPath]byte
	TenantID    uint32
	OwnerTenant uint32
	Verdict     uint32
	Pad         uint32
}

// TLSEvent mirrors struct dbg_tls_event.
type TLSEvent struct {
	Hdr       DbgHdr
	SNI       [MaxSNI]byte
	Handshake uint32
	Version   uint32
	Cipher    uint32
	Pad       uint32
}

// ConfigMap mirrors struct dbg_config - the single-element array map
// "config_map" populated by the manager.
type ConfigMap struct {
	PGPort         uint16
	MySQLPort      uint16
	SQLIEnabled    uint8
	DropEnabled    uint8
	PIIPrescan     uint8
	ExfilEnabled   uint8
	RIDSAlertOnly  uint8
	LineageEnabled uint8
	Pad            [2]byte
}
