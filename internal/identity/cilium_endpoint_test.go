package identity

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// endpointListJSON mimics the real Cilium agent GET /v1/endpoint response:
// an array of endpoints, each with status.networking.addressing[] and
// status.identity.{id,labels}.
const endpointListJSON = `[
  {
    "id": 42,
    "status": {
      "identity": { "id": 12345, "labels": ["k8s:app=api-server", "k8s:io.kubernetes.pod.namespace=demo"] },
      "networking": { "addressing": [ { "ipv4": "10.244.1.17", "ipv6": "" } ] }
    }
  },
  {
    "id": 43,
    "status": {
      "identity": { "id": 54321, "labels": ["k8s:app=attacker"] },
      "networking": { "addressing": [ { "ipv4": "10.244.1.99" } ] }
    }
  }
]`

// TestLookupEndpointsMatchesIP verifies the client parses the real agent's
// endpoint list and maps a client IP to its security identity id + labels.
func TestLookupEndpointsMatchesIP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/endpoint" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(endpointListJSON))
	}))
	defer srv.Close()

	c := NewCiliumClient(srv.URL, 2*time.Second)

	id, labels, ok := c.LookupForIP("10.244.1.17")
	if !ok {
		t.Fatalf("expected a match for 10.244.1.17, got ok=false")
	}
	if id != "12345" {
		t.Errorf("id: got %q, want 12345", id)
	}
	if len(labels) != 2 || labels[0] != "k8s:app=api-server" {
		t.Errorf("labels: got %v, want [k8s:app=api-server ...]", labels)
	}

	// Second endpoint.
	id2, _, ok2 := c.LookupForIP("10.244.1.99")
	if !ok2 || id2 != "54321" {
		t.Errorf("second endpoint: got id=%q ok=%v, want 54321/true", id2, ok2)
	}

	// Unknown IP → no information (ok=false), cached without error.
	if _, _, ok3 := c.LookupForIP("10.244.9.9"); ok3 {
		t.Errorf("unknown IP: expected ok=false")
	}
}

// TestLookupStubFallback verifies that when the endpoint list yields nothing
// (an http stub that only answers /v1/identity?ip=), the client falls back to
// the simple stub shape used by scripts/test-cilium.sh.
func TestLookupStubFallback(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/identity":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"security_identity":{"id":99001,"labels":["k8s:app=legacy"]}}`))
		default:
			// /v1/endpoint etc. → not the array the real agent serves.
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	c := NewCiliumClient(srv.URL, 2*time.Second)
	id, labels, ok := c.LookupForIP("10.0.0.5")
	if !ok || id != "99001" {
		t.Fatalf("stub fallback: got id=%q ok=%v, want 99001/true", id, ok)
	}
	if len(labels) != 1 || labels[0] != "k8s:app=legacy" {
		t.Errorf("stub labels: got %v", labels)
	}
}
