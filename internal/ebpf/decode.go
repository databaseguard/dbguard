package ebpf

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/databaseguard/dbguard/internal/events"
)

// severityNames maps kernel severity ints to pipeline severities.
var severityNames = map[uint32]events.Severity{
	0: events.SevInfo,
	1: events.SevLow,
	2: events.SevMedium,
	3: events.SevHigh,
	4: events.SevCritical,
}

// engineNames maps kernel engine ints to pipeline engine strings.
var engineNames = map[uint32]string{
	EngUnknown:  "unknown",
	EngPostgres: "postgres",
	EngMySQL:    "mysql",
	EngSQLite:   "sqlite",
}

// newReader wraps a record for binary.Read.
func newReader(b []byte) *bytes.Reader { return bytes.NewReader(b) }

// DecodeEvent decodes any ring-buffer record into a pipeline event.
// The first 4 bytes are hdr.type (little endian).
func DecodeEvent(b []byte) (*events.Event, error) {
	if len(b) < 64 {
		return nil, fmt.Errorf("ebpf: short record %d bytes", len(b))
	}
	typ := binary.LittleEndian.Uint32(b[0:4])
	switch typ {
	case EvtQuery:
		return decodeQuery(b)
	case EvtAlert:
		return decodeAlert(b)
	case EvtFlow, EvtConn:
		return decodeFlow(b, typ)
	case EvtExfil:
		return decodeExfil(b)
	case EvtExec:
		return decodeExec(b)
	case EvtFile:
		return decodeFile(b)
	case EvtLineage:
		return decodeLineage(b)
	case EvtTenant:
		return decodeTenant(b)
	case EvtTLS:
		return decodeTLS(b)
	default:
		return nil, fmt.Errorf("ebpf: unknown event type %d", typ)
	}
}

func hdrOf(b []byte) DbgHdr {
	var h DbgHdr
	h.Type = binary.LittleEndian.Uint32(b[0:4])
	h.Action = binary.LittleEndian.Uint32(b[4:8])
	h.PID = binary.LittleEndian.Uint32(b[8:12])
	h.TID = binary.LittleEndian.Uint32(b[12:16])
	h.UID = binary.LittleEndian.Uint32(b[16:20])
	h.Severity = binary.LittleEndian.Uint32(b[20:24])
	h.RuleID = binary.LittleEndian.Uint32(b[24:28])
	h.Engine = binary.LittleEndian.Uint32(b[28:32])
	h.Cgroup = binary.LittleEndian.Uint64(b[32:40])
	h.TsNS = binary.LittleEndian.Uint64(b[40:48])
	h.Session = binary.LittleEndian.Uint64(b[48:56])
	h.DataLen = binary.LittleEndian.Uint32(b[56:60])
	return h
}

func (h DbgHdr) base() events.Event {
	ev := events.Event{
		PID:       h.PID,
		TID:       h.TID,
		UID:       h.UID,
		CgroupID:  h.Cgroup,
		SessionID: h.Session,
		Severity:  severityNames[h.Severity],
		Time:      time.Now().UTC(),
		ID:        events.NewID(),
	}
	if !ev.Time.IsZero() && h.TsNS > 0 {
		// ktime ns is monotonic; align wall clock loosely (good enough for UI)
		ev.Time = time.Now().UTC().Add(0)
	}
	switch h.Action {
	case ActDrop:
		ev.AddAction(events.ActDrop)
	case ActReset:
		ev.AddAction(events.ActReset)
	case ActQuarantine:
		ev.AddAction(events.ActQuarantine)
	case ActKill:
		ev.AddAction(events.ActKill)
	case ActAlert:
		ev.AddAction(events.ActAlert)
	}
	return ev
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func addrBytes(a [16]byte, family uint32) string {
	if family == 2 { // AF_INET
		return net.IP(a[:4]).String()
	}
	if isZero16(a) {
		return ""
	}
	return net.IP(a[:]).String()
}

func isZero16(a [16]byte) bool {
	for _, c := range a {
		if c != 0 {
			return false
		}
	}
	return true
}

func decodeQuery(b []byte) (*events.Event, error) {
	var q QueryEvent
	if err := binary.Read(newReader(b), binary.LittleEndian, &q); err != nil {
		return nil, err
	}
	ev := q.Hdr.base()
	ev.Type = events.EvQueryAudit
	ev.Engine = engineNames[q.Hdr.Engine]
	ev.Source = "kernel"
	sql := cstr(q.SQL[:min(int(q.SQLLen), MaxSQL)])
	ev.SQL = sql
	ev.SQLLen = int(q.SQLLen)
	ev.Binary = cstr(q.Comm[:])
	ev.ClientIP = addrBytes(q.SAddr, q.Family)
	ev.ServerIP = addrBytes(q.DAddr, q.Family)
	ev.ClientPort = q.Sport
	ev.ServerPort = q.DPort

	var fmeta []string
	if q.Flags&QFPIIDigits != 0 {
		fmeta = append(fmeta, "pii_digits")
	}
	if q.Flags&QFLuhnHit != 0 {
		fmeta = append(fmeta, "luhn_hit")
		ev.AddFinding(events.Finding{Kind: "credit_card-like", Detail: "kernel Luhn pre-scan matched a digit run", Confidence: 0.6})
	}
	if q.Flags&QFSSNLike != 0 {
		fmeta = append(fmeta, "ssn_like")
	}
	if q.Flags&QFSecretLike != 0 {
		fmeta = append(fmeta, "secret_like")
	}
	if q.Flags&QFDDL != 0 {
		fmeta = append(fmeta, "ddl")
	}
	if q.Flags&QFBulkSelect != 0 {
		fmeta = append(fmeta, "bulk_select")
	}
	if q.Flags&QFSQLIHint != 0 {
		fmeta = append(fmeta, "sqli_hint")
	}
	for _, f := range fmeta {
		ev.MetaSet("kflag_"+f, "1")
	}
	return &ev, nil
}

func decodeAlert(b []byte) (*events.Event, error) {
	var a AlertEvent
	if err := binary.Read(newReader(b), binary.LittleEndian, &a); err != nil {
		return nil, err
	}
	ev := a.Hdr.base()
	ev.Engine = engineNames[a.Hdr.Engine]
	ev.Source = "kernel"
	ev.Binary = cstr(a.Comm[:])
	msg := cstr(a.Msg[:])
	ev.Message = msg
	switch a.Code {
	case AlcSQLi:
		ev.Type = events.EvSQLi
		ev.Severity = maxSev(ev.Severity, events.SevHigh)
	case AlcConnSpike:
		ev.Type = events.EvConnAnomaly
		ev.Severity = maxSev(ev.Severity, events.SevMedium)
	case AlcAuthFail:
		ev.Type = events.EvAuthAnomaly
		ev.Severity = maxSev(ev.Severity, events.SevMedium)
	case AlcTenant:
		ev.Type = events.EvTenant
		ev.Severity = maxSev(ev.Severity, events.SevHigh)
	case AlcPII:
		ev.Type = events.EvPIIHit
		ev.Severity = maxSev(ev.Severity, events.SevHigh)
	case AlcExfil:
		ev.Type = events.EvExfil
		ev.Severity = maxSev(ev.Severity, events.SevCritical)
	case AlcRIDSExec:
		ev.Type = events.EvExecve
		ev.Severity = maxSev(ev.Severity, events.SevCritical)
	case AlcRIDSFile:
		ev.Type = events.EvFileAccess
		ev.Severity = maxSev(ev.Severity, events.SevHigh)
	default:
		ev.Type = events.EvPolicyDecision
	}
	return &ev, nil
}

func decodeFlow(b []byte, typ uint32) (*events.Event, error) {
	var f FlowEvent
	if err := binary.Read(newReader(b), binary.LittleEndian, &f); err != nil {
		return nil, err
	}
	ev := f.Hdr.base()
	if typ == EvtConn && f.Event == 1 {
		ev.Type = events.EvConnOpen
	} else if typ == EvtConn && f.Event == 2 {
		ev.Type = events.EvConnClose
	} else {
		ev.Type = events.EvConnOpen
	}
	ev.Source = "kernel"
	// conn_anomaly/exfil write IPv4 addresses as 4 network-order bytes
	// (AF_INET); pass family=2 so these format as dotted-quad instead of
	// being misread as a 16-byte IPv6 address.
	ev.ClientIP = addrBytes(f.SAddr, 2)
	ev.ServerIP = addrBytes(f.DAddr, 2)
	ev.ClientPort = f.Sport
	ev.ServerPort = f.DPort
	ev.MetaSet("bytes", fmtUint(f.Bytes))
	ev.MetaSet("packets", fmtUint(f.Packets))
	ev.MetaSet("flow_event", fmtUint(uint64(f.Event)))
	ev.Severity = maxSev(ev.Severity, events.SevInfo)
	return &ev, nil
}

func decodeExfil(b []byte) (*events.Event, error) {
	var x ExfilEvent
	if err := binary.Read(newReader(b), binary.LittleEndian, &x); err != nil {
		return nil, err
	}
	ev := x.Hdr.base()
	ev.Type = events.EvExfil
	ev.Source = "kernel"
	// exfil breaker is IPv4-only (see exfil_breaker.bpf.c): addresses are
	// 4 network-order bytes. family=2 => dotted-quad, so the quarantine
	// path recognises it as IPv4 instead of logging "IPv6 unsupported".
	ev.ClientIP = addrBytes(x.SAddr, 2)
	ev.ServerIP = addrBytes(x.DAddr, 2)
	ev.ClientPort = x.Sport
	ev.ServerPort = x.DPort
	ev.Message = fmt.Sprintf("bulk-dump burst: %d bytes in %dms window (rate %d KB/s)",
		x.BytesWindow, x.WindowMS, x.RateKbps)
	ev.MetaSet("bytes_window", fmtUint(x.BytesWindow))
	ev.MetaSet("bytes_total", fmtUint(x.BytesTotal))
	ev.MetaSet("rate_kbps", fmtUint(uint64(x.RateKbps)))
	ev.Severity = maxSev(ev.Severity, events.SevCritical)
	return &ev, nil
}

func decodeExec(b []byte) (*events.Event, error) {
	var e ExecEvent
	if err := binary.Read(newReader(b), binary.LittleEndian, &e); err != nil {
		return nil, err
	}
	ev := e.Hdr.base()
	ev.Type = events.EvExecve
	ev.Source = "kernel"
	ev.Binary = cstr(e.Comm[:])
	path := cstr(e.Path[:])
	argv := cstr(e.Argv[:])
	ev.Message = "execve from DB process: " + path
	ev.MetaSet("path", path)
	ev.MetaSet("argv", argv)
	ev.Severity = maxSev(ev.Severity, events.SevCritical)
	return &ev, nil
}

func decodeFile(b []byte) (*events.Event, error) {
	var f FileEvent
	if err := binary.Read(newReader(b), binary.LittleEndian, &f); err != nil {
		return nil, err
	}
	ev := f.Hdr.base()
	ev.Type = events.EvFileAccess
	ev.Source = "kernel"
	ev.Binary = cstr(f.Comm[:])
	path := cstr(f.Path[:])
	ev.Message = "sensitive file access: " + path
	ev.MetaSet("path", path)
	ev.MetaSet("tenant_id", fmtUint(uint64(f.TenantID)))
	ev.Severity = maxSev(ev.Severity, events.SevHigh)
	return &ev, nil
}

func decodeLineage(b []byte) (*events.Event, error) {
	var l LineageEvent
	if err := binary.Read(newReader(b), binary.LittleEndian, &l); err != nil {
		return nil, err
	}
	ev := l.Hdr.base()
	ev.Type = events.EvLineage
	ev.Source = "kernel"
	ev.Route = cstr(l.Route[:])
	ev.AppPID = l.AppPID
	ev.SessionID = l.SockCookie
	switch l.Flags {
	case 1:
		ev.Message = "pool hijack suspected: unexpected route on pooled connection"
		ev.Severity = maxSev(ev.Severity, events.SevHigh)
	case 2:
		ev.Message = "query has no matching application route context"
		ev.Severity = maxSev(ev.Severity, events.SevMedium)
	default:
		ev.Message = "lineage correlation verdict"
	}
	ev.MetaSet("lineage_flags", fmtUint(uint64(l.Flags)))
	return &ev, nil
}

func decodeTenant(b []byte) (*events.Event, error) {
	var t TenantEvent
	if err := binary.Read(newReader(b), binary.LittleEndian, &t); err != nil {
		return nil, err
	}
	ev := t.Hdr.base()
	ev.Type = events.EvTenant
	ev.Source = "kernel"
	path := cstr(t.Path[:])
	ev.Message = "cross-tenant isolation violation: " + path
	ev.MetaSet("path", path)
	ev.MetaSet("tenant_id", fmtUint(uint64(t.TenantID)))
	ev.MetaSet("owner_tenant", fmtUint(uint64(t.OwnerTenant)))
	ev.Severity = maxSev(ev.Severity, events.SevHigh)
	return &ev, nil
}

func decodeTLS(b []byte) (*events.Event, error) {
	var t TLSEvent
	if err := binary.Read(newReader(b), binary.LittleEndian, &t); err != nil {
		return nil, err
	}
	ev := t.Hdr.base()
	ev.Type = events.EvTLSSession
	ev.Source = "kernel"
	ev.MetaSet("sni", cstr(t.SNI[:]))
	ev.MetaSet("cipher", fmtUint(uint64(t.Cipher)))
	ev.Severity = events.SevInfo
	return &ev, nil
}

func maxSev(a, b events.Severity) events.Severity {
	if a.Order() >= b.Order() {
		return a
	}
	return b
}

func fmtUint(u uint64) string {
	return fmt.Sprintf("%d", u)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
