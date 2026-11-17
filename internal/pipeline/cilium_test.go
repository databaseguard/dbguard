package pipeline

import (
	"testing"

	"github.com/databaseguard/dbguard/internal/enrich"
	"github.com/databaseguard/dbguard/internal/events"
)

// ciliumResolver is a fakeResolver that also implements enrich.CiliumLookup.
type ciliumResolver struct{ fakeResolver }

func (ciliumResolver) LookupForIP(ip string) (string, []string, bool) {
	if ip == "10.1.2.3" {
		return "identity-42", []string{"k8s:app=api-server"}, true
	}
	return "", nil, false
}

// The enrich stage must stamp ev.CiliumID + labels + meta from the client IP
// when the resolver supports Cilium lookups, and degrade silently otherwise.
func TestEnrichStampsCiliumIdentity(t *testing.T) {
	p := &Pipeline{res: ciliumResolver{}}

	ev := &events.Event{Type: events.EvPolicyDecision, ClientIP: "10.1.2.3"}
	p.enrichStage(ev)
	if ev.CiliumID != "identity-42" || ev.MetaGet("cilium_identity") != "identity-42" {
		t.Fatalf("expected cilium identity stamped, got CiliumID=%q meta=%q",
			ev.CiliumID, ev.MetaGet("cilium_identity"))
	}
	if len(ev.CiliumLabels) != 1 || ev.CiliumLabels[0] != "k8s:app=api-server" {
		t.Fatalf("expected cilium labels stamped, got %v", ev.CiliumLabels)
	}

	ev2 := &events.Event{Type: events.EvPolicyDecision, ClientIP: "9.9.9.9"}
	p.enrichStage(ev2)
	if ev2.CiliumID != "" {
		t.Fatalf("expected no identity for unknown IP, got %q", ev2.CiliumID)
	}

	p3 := &Pipeline{res: fakeResolver{}}
	ev3 := &events.Event{Type: events.EvPolicyDecision, ClientIP: "10.1.2.3"}
	p3.enrichStage(ev3)
	if ev3.CiliumID != "" {
		t.Fatalf("non-Cilium resolver must not stamp identity")
	}
	var _ enrich.CiliumLookup = ciliumResolver{}
}
