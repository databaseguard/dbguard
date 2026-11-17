package config

import "testing"

func TestEffectiveProxiesPlural(t *testing.T) {
	c := &Config{Proxies: []ProxyConfig{
		{Enabled: true, Listen: "127.0.0.1:6432", Upstream: "127.0.0.1:5432", Engine: "postgres"},
		{Enabled: true, Listen: "127.0.0.1:6433", Upstream: "127.0.0.1:3306", Engine: "mysql"},
		{Enabled: false, Listen: "127.0.0.1:7000", Upstream: "127.0.0.1:7001", Engine: "mysql"}, // skipped
		{Enabled: true, Listen: "", Upstream: "x"},                                              // skipped: no listen
	}}
	got := c.EffectiveProxies()
	if len(got) != 2 {
		t.Fatalf("want 2 effective proxies, got %d: %+v", len(got), got)
	}
	if got[0].Engine != "postgres" || got[1].Engine != "mysql" {
		t.Fatalf("unexpected engines: %+v", got)
	}
}

func TestEffectiveProxiesSingularBackCompat(t *testing.T) {
	c := &Config{Proxy: ProxyConfig{Enabled: true, Listen: "127.0.0.1:6432", Upstream: "127.0.0.1:5432"}}
	got := c.EffectiveProxies()
	if len(got) != 1 || got[0].Engine != "postgres" { // engine defaulted
		t.Fatalf("back-compat single proxy failed: %+v", got)
	}
}

func TestEffectiveProxiesDisabled(t *testing.T) {
	c := &Config{Proxy: ProxyConfig{Enabled: false, Listen: "x", Upstream: "y"}}
	if n := len(c.EffectiveProxies()); n != 0 {
		t.Fatalf("want 0 when disabled, got %d", n)
	}
}
