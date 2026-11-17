package tenant

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/databaseguard/dbguard/internal/config"
	"github.com/databaseguard/dbguard/internal/events"
)

// testTenantCfg returns three tenants: acme and globex with filesystem and
// network scopes, initech claiming a nested path inside acme's tree (to
// exercise longest-prefix resolution) and opting out of network checks.
func testTenantCfg() config.TenantConfig {
	return config.TenantConfig{
		Enabled: true,
		Tenants: []config.TenantDef{
			{ID: "acme", Cgroups: []string{"acme.service"},
				AllowedPaths: []string{"/data/acme"}, AllowedCIDRs: []string{"10.0.0.0/8"}},
			{ID: "globex", Cgroups: []string{"globex.service"},
				AllowedPaths: []string{"/data/globex"}, AllowedCIDRs: []string{"192.168.0.0/16"}},
			{ID: "initech", Cgroups: []string{"initech.service"},
				AllowedPaths: []string{"/data/acme/shared"}},
		},
	}
}

func fmtID(id uint32) string { return strconv.FormatUint(uint64(id), 10) }

func TestRegistryPrefixMatching(t *testing.T) {
	reg, err := NewRegistry(testTenantCfg())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	if owner, ok := reg.OwnerForPath("/data/acme/db/customers.db"); !ok || owner.Name != "acme" {
		t.Errorf("OwnerForPath(acme) = %v, %v; want acme", owner, ok)
	}
	if owner, ok := reg.OwnerForPath("/data/globex/leads.csv"); !ok || owner.Name != "globex" {
		t.Errorf("OwnerForPath(globex) = %v, %v; want globex", owner, ok)
	}
	// Longest prefix wins across tenants.
	if owner, ok := reg.OwnerForPath("/data/acme/shared/tmp.txt"); !ok || owner.Name != "initech" {
		t.Errorf("longest prefix must win, got %v, %v", owner, ok)
	}
	// Boundary-aware: sibling directory is unmanaged.
	if owner, ok := reg.OwnerForPath("/data/acme-old/x"); ok {
		t.Errorf("sibling path must not match, got %v", owner)
	}
	// Unmanaged paths have no owner.
	if _, ok := reg.OwnerForPath("/etc/passwd"); ok {
		t.Errorf("unmanaged path must have no owner")
	}
	// Cgroup fragment resolution.
	if ct, ok := reg.ByCgroup("/sys/fs/cgroup/system.slice/acme.service/app.service"); !ok || ct.Name != "acme" {
		t.Errorf("ByCgroup(acme) = %v, %v; want acme", ct, ok)
	}
	if _, ok := reg.ByCgroup("/sys/fs/cgroup/system.slice/other.service"); ok {
		t.Errorf("unknown cgroup must not resolve")
	}
}

func TestGuardCrossTenantFile(t *testing.T) {
	var published []*events.Event
	cfg := testTenantCfg()
	g, err := New(cfg, nil, func(ev *events.Event) { published = append(published, ev) })
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if g.Name() != "tenant" {
		t.Fatalf("Name() = %q, want tenant", g.Name())
	}

	globexID := StableID("globex")
	ev := &events.Event{ID: events.NewID(), Type: events.EvFileAccess, Time: time.Now(),
		PID: 8000, Severity: events.SevInfo}
	ev.MetaSet("path", "/data/acme/customers.sql")
	ev.MetaSet("tenant_id", fmtID(globexID))
	fs := g.Evaluate(ev)
	if len(fs) != 1 || fs[0].Kind != KindCrossTenantFile {
		t.Fatalf("expected one %s finding, got %+v", KindCrossTenantFile, fs)
	}
	if ev.Severity != events.SevHigh {
		t.Errorf("cross-tenant file access must be high, got %q", ev.Severity)
	}
	if !ev.HasAction(events.ActDeny) || !ev.HasAction(events.ActQuarantine) {
		t.Errorf("expected deny+quarantine, got %v", ev.Actions)
	}
	if !strings.Contains(fs[0].Detail, "globex") || !strings.Contains(fs[0].Detail, "acme") {
		t.Errorf("detail should name caller and owner, got %q", fs[0].Detail)
	}
	if len(published) != 1 {
		t.Fatalf("expected one synthesized tenant.violation event, got %d", len(published))
	}
	if pub := published[0]; pub.Type != events.EvTenant || pub.Source != "tenant" ||
		pub.Severity != events.SevHigh || pub.MetaGet("kind") != "cross_tenant_file" {
		t.Errorf("bad synthesized event: %+v", pub)
	}

	// Same tenant → silent.
	ok := &events.Event{ID: events.NewID(), Type: events.EvFileAccess}
	ok.MetaSet("path", "/data/acme/customers.sql")
	ok.MetaSet("tenant_id", fmtID(StableID("acme")))
	if fs := g.Evaluate(ok); len(fs) != 0 || len(ok.Actions) != 0 {
		t.Errorf("own-tenant access must be silent, got %+v / %v", fs, ok.Actions)
	}
	// No caller context → cannot judge, silent.
	unknown := &events.Event{ID: events.NewID(), Type: events.EvFileAccess}
	unknown.MetaSet("path", "/data/acme/customers.sql")
	if fs := g.Evaluate(unknown); len(fs) != 0 {
		t.Errorf("caller-less access must be silent, got %+v", fs)
	}

	// AlertOnly keeps deny but drops quarantine.
	cfg.AlertOnly = true
	g2, err := New(cfg, nil, nil)
	if err != nil {
		t.Fatalf("New(alertOnly): %v", err)
	}
	ev2 := &events.Event{ID: events.NewID(), Type: events.EvFileAccess}
	ev2.MetaSet("path", "/data/globex/leads.csv")
	ev2.MetaSet("tenant_id", fmtID(StableID("acme")))
	if fs := g2.Evaluate(ev2); len(fs) != 1 {
		t.Fatalf("alert-only must still report the finding, got %+v", fs)
	}
	if !ev2.HasAction(events.ActDeny) || ev2.HasAction(events.ActQuarantine) {
		t.Errorf("alert-only must keep deny and drop quarantine, got %v", ev2.Actions)
	}
}

func TestGuardCIDRAndNetworkViolation(t *testing.T) {
	reg, err := NewRegistry(testTenantCfg())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	acme, _ := reg.ByName("acme")
	if !reg.CIDRAllow(acme.ID, "10.1.2.3") {
		t.Errorf("10.1.2.3 must be inside 10.0.0.0/8")
	}
	if reg.CIDRAllow(acme.ID, "192.168.1.1") {
		t.Errorf("192.168.1.1 must be outside 10.0.0.0/8")
	}
	if reg.CIDRAllow(acme.ID, "not-an-ip") {
		t.Errorf("unparseable address must deny")
	}
	if reg.CIDRAllow(99999, "10.0.0.1") {
		t.Errorf("unknown tenant must deny")
	}

	g, err := New(testTenantCfg(), nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := &events.Event{ID: events.NewID(), Type: events.EvConnOpen, Time: time.Now(),
		ClientIP: "203.0.113.9", Severity: events.SevInfo}
	ev.MetaSet("tenant_id", fmtID(acme.ID))
	fs := g.Evaluate(ev)
	if len(fs) != 1 || fs[0].Kind != KindNetworkViolation {
		t.Fatalf("expected one %s finding, got %+v", KindNetworkViolation, fs)
	}
	if !ev.HasAction(events.ActDeny) {
		t.Errorf("network violation must deny, got %v", ev.Actions)
	}
	// Allowed source → silent.
	ok := &events.Event{ID: events.NewID(), Type: events.EvConnOpen, ClientIP: "10.20.30.40"}
	ok.MetaSet("tenant_id", fmtID(acme.ID))
	if fs := g.Evaluate(ok); len(fs) != 0 {
		t.Errorf("allowed source must be silent, got %+v", fs)
	}
	// Tenant without CIDRs opted out (initech).
	initech, _ := reg.ByName("initech")
	opt := &events.Event{ID: events.NewID(), Type: events.EvConnOpen, ClientIP: "1.2.3.4"}
	opt.MetaSet("tenant_id", fmtID(initech.ID))
	if fs := g.Evaluate(opt); len(fs) != 0 {
		t.Errorf("tenant without cidrs must not be network-checked, got %+v", fs)
	}
}

func TestStableIDDeterminism(t *testing.T) {
	// FNV-1a 32-bit known-answer vectors (offset basis and "a").
	if got := StableID(""); got != 2166136261 {
		t.Errorf("StableID(\"\") = %d, want FNV-1a offset basis 2166136261", got)
	}
	if got := StableID("a"); got != 0xe40c292c {
		t.Errorf("StableID(\"a\") = %#x, want 0xe40c292c", got)
	}
	if StableID("acme") == StableID("globex") {
		t.Errorf("distinct names must hash to distinct ids")
	}
	reg, err := NewRegistry(testTenantCfg())
	if err != nil {
		t.Fatalf("NewRegistry: %v", err)
	}
	for _, tn := range reg.Tenants() {
		if tn.ID != StableID(tn.Name) {
			t.Errorf("tenant %q id %d does not match StableID %d", tn.Name, tn.ID, StableID(tn.Name))
		}
		if got, ok := reg.ByID(tn.ID); !ok || got.Name != tn.Name {
			t.Errorf("ByID(%d) roundtrip failed: %v, %v", tn.ID, got, ok)
		}
	}
}

func TestGuardDBMismatch(t *testing.T) {
	g, err := New(testTenantCfg(), nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ev := &events.Event{ID: events.NewID(), Type: events.EvQueryAudit, Database: "globex_main"}
	ev.Labels = map[string]string{"tenant": "acme"}
	fs := g.Evaluate(ev)
	if len(fs) != 1 || fs[0].Kind != KindDBMismatch {
		t.Fatalf("expected one %s finding, got %+v", KindDBMismatch, fs)
	}
	if ev.Severity != events.SevMedium || !ev.HasAction(events.ActAlert) {
		t.Errorf("db mismatch must be medium+alert, got %q / %v", ev.Severity, ev.Actions)
	}
	// Own-tenant database stays silent.
	ok := &events.Event{ID: events.NewID(), Type: events.EvQueryAudit, Database: "acme_crm"}
	ok.Labels = map[string]string{"tenant": "acme"}
	if fs := g.Evaluate(ok); len(fs) != 0 {
		t.Errorf("own database must be silent, got %+v", fs)
	}
	// Unknown label cannot be verified.
	skip := &events.Event{ID: events.NewID(), Type: events.EvQueryAudit, Database: "globex_main"}
	skip.Labels = map[string]string{"tenant": "unregistered"}
	if fs := g.Evaluate(skip); len(fs) != 0 {
		t.Errorf("unknown label must be skipped, got %+v", fs)
	}
	if err := g.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}
