package proxy

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/databaseguard/dbguard/internal/policy"
)

// evalFunc adapts a func to the Evaluator interface.
type evalFunc func(*policy.Context) policy.Decision

func (f evalFunc) Evaluate(c *policy.Context) policy.Decision { return f(c) }

// pgStartup builds a minimal 3.0 StartupMessage with user+database.
func pgStartup(user, db string) []byte {
	body := []byte{0, 3, 0, 0} // protocol 3.0
	body = append(body, []byte("user")...)
	body = append(body, 0)
	body = append(body, []byte(user)...)
	body = append(body, 0)
	body = append(body, []byte("database")...)
	body = append(body, 0)
	body = append(body, []byte(db)...)
	body = append(body, 0)
	body = append(body, 0)
	out := make([]byte, 4+len(body))
	binary.BigEndian.PutUint32(out[0:4], uint32(4+len(body)))
	copy(out[4:], body)
	return out
}

// pgQuery builds a simple Query ('Q') message.
func pgQuery(sql string) []byte {
	payload := append([]byte(sql), 0)
	out := make([]byte, 1+4+len(payload))
	out[0] = 'Q'
	binary.BigEndian.PutUint32(out[1:5], uint32(4+len(payload)))
	copy(out[5:], payload)
	return out
}

func TestProxyBlocksDeniedQueryInline(t *testing.T) {
	// fake upstream DB: records everything it receives
	upLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer upLn.Close()
	gotCh := make(chan []byte, 16)
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 4096)
		for {
			n, err := c.Read(b)
			if n > 0 {
				gotCh <- append([]byte(nil), b[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()

	// policy: deny any SQL containing "secrets", allow the rest
	eng := evalFunc(func(c *policy.Context) policy.Decision {
		for _, tb := range c.Tables {
			if tb == "secrets" {
				return policy.Decision{Allowed: false, RuleIDs: []string{"block.secrets"}}
			}
		}
		return policy.Decision{Allowed: true}
	})

	p := New(Config{Listen: "127.0.0.1:0", Upstream: upLn.Addr().String(), Engine: "postgres"}, eng, nil, nil)
	pLn, _ := net.Listen("tcp", "127.0.0.1:0")
	p.ln = pLn
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			conn, err := pLn.Accept()
			if err != nil {
				return
			}
			go p.handle(ctx, conn)
		}
	}()

	cli, err := net.Dial("tcp", pLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	cli.Write(pgStartup("app", "appdb"))
	time.Sleep(100 * time.Millisecond)
	// drain startup forwarded to upstream
	select {
	case <-gotCh:
	case <-time.After(time.Second):
		t.Fatal("startup not forwarded")
	}

	// 1) ALLOWED query must reach upstream
	cli.Write(pgQuery("SELECT id FROM customers"))
	select {
	case g := <-gotCh:
		if !contains(g, "SELECT id FROM customers") {
			t.Fatalf("allowed query not forwarded verbatim: %q", g)
		}
	case <-time.After(time.Second):
		t.Fatal("allowed query was NOT forwarded (should pass)")
	}

	// 2) DENIED query must NOT reach upstream, client gets an error
	cli.Write(pgQuery("SELECT * FROM secrets"))
	cli.SetReadDeadline(time.Now().Add(time.Second))
	resp := make([]byte, 1024)
	n, _ := cli.Read(resp)
	if n == 0 || resp[0] != 'E' {
		t.Fatalf("expected ErrorResponse 'E' to client, got %d bytes starting %v", n, resp[:min(n, 1)])
	}
	if !contains(resp[:n], "blocked by policy") {
		t.Fatalf("error message missing policy text: %q", resp[:n])
	}
	// upstream must NOT have received the secrets query
	select {
	case g := <-gotCh:
		if contains(g, "secrets") {
			t.Fatalf("DENIED query LEAKED to upstream: %q", g)
		}
	case <-time.After(300 * time.Millisecond):
		// good: nothing forwarded
	}
	t.Log("OK: allowed query forwarded; denied query blocked inline, never reached upstream")
}

func contains(b []byte, s string) bool {
	return string(b) != "" && (len(s) == 0 || indexOf(b, s) >= 0)
}
func indexOf(b []byte, s string) int {
	bs := string(b)
	for i := 0; i+len(s) <= len(bs); i++ {
		if bs[i:i+len(s)] == s {
			return i
		}
	}
	return -1
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// sslRequest builds a PostgreSQL SSLRequest (len=8, magic 80877103).
func sslRequest() []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint32(b[0:4], 8)
	binary.BigEndian.PutUint32(b[4:8], 80877103)
	return b
}

// TestProxyDeclinesSSLRequest verifies the proxy replies 'N' to an SSLRequest
// (len is exactly 8, which used to be mis-parsed as a startup and forwarded
// upstream, hanging psql's default sslmode=prefer) and then forwards the
// following plaintext startup upstream.
func TestProxyDeclinesSSLRequest(t *testing.T) {
	upLn, _ := net.Listen("tcp", "127.0.0.1:0")
	defer upLn.Close()
	gotCh := make(chan []byte, 16)
	go func() {
		c, err := upLn.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		b := make([]byte, 4096)
		for {
			n, err := c.Read(b)
			if n > 0 {
				gotCh <- append([]byte(nil), b[:n]...)
			}
			if err != nil {
				return
			}
		}
	}()

	eng := evalFunc(func(c *policy.Context) policy.Decision { return policy.Decision{Allowed: true} })
	p := New(Config{Listen: "127.0.0.1:0", Upstream: upLn.Addr().String(), Engine: "postgres"}, eng, nil, nil)
	pLn, _ := net.Listen("tcp", "127.0.0.1:0")
	p.ln = pLn
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		for {
			conn, err := pLn.Accept()
			if err != nil {
				return
			}
			go p.handle(ctx, conn)
		}
	}()

	cli, err := net.Dial("tcp", pLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()

	// SSLRequest -> expect a single 'N', and NOTHING forwarded upstream.
	cli.Write(sslRequest())
	cli.SetReadDeadline(time.Now().Add(time.Second))
	one := make([]byte, 1)
	if _, err := cli.Read(one); err != nil {
		t.Fatalf("no SSL decline byte returned: %v", err)
	}
	if one[0] != 'N' {
		t.Fatalf("expected 'N' decline, got %q", one[0])
	}
	select {
	case g := <-gotCh:
		t.Fatalf("SSLRequest must NOT be forwarded upstream, but upstream received %q", g)
	case <-time.After(200 * time.Millisecond):
	}

	// Plaintext startup after the decline must be forwarded upstream.
	cli.Write(pgStartup("app", "appdb"))
	select {
	case g := <-gotCh:
		if !contains(g, "appdb") {
			t.Fatalf("startup after SSL decline not forwarded verbatim: %q", g)
		}
	case <-time.After(time.Second):
		t.Fatal("startup after SSL decline was NOT forwarded (SSL handling bug)")
	}
}
