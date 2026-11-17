package policy

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestIdentityRuleGating(t *testing.T) {
	doc := `api_version: dbguard.io/v1
kind: DbGuardPolicy
metadata: {name: ident}
spec:
  default_action: deny
  rules:
    - id: allow.api-server
      identities: [k8s:app=api-server]
      actions: [allow]
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "50.yaml"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	eng := New(nil)
	if err := eng.SetDirs([]string{dir}, false); err != nil {
		t.Fatal(err)
	}
	base := func(labels []string) *Context {
		return &Context{Engine: "postgres", SQL: "SELECT 1", CiliumLabels: labels, Now: time.Now()}
	}
	// Allowed identity (label substring "api-server" matches the rule).
	if d := eng.Evaluate(base([]string{"k8s:app=api-server"})); !d.Allowed {
		t.Fatalf("api-server identity must be allowed, got %+v", d)
	}
	// A different identity -> default deny.
	if d := eng.Evaluate(base([]string{"k8s:app=attacker"})); d.Allowed {
		t.Fatalf("non-allowed identity must be denied, got %+v", d)
	}
	// No identity at all (Cilium off) -> default deny; identity rule can't match.
	if d := eng.Evaluate(base(nil)); d.Allowed {
		t.Fatalf("missing identity must fall through to default deny, got %+v", d)
	}
}

func TestMatchIdentityByIDAndLabel(t *testing.T) {
	if !matchIdentity([]string{"12345"}, "12345", nil) {
		t.Fatal("id match failed")
	}
	if !matchIdentity([]string{"api-server"}, "999", []string{"k8s:app=api-server"}) {
		t.Fatal("label substring match failed")
	}
	if matchIdentity([]string{"api-server"}, "", nil) {
		t.Fatal("no identity must not match")
	}
}
