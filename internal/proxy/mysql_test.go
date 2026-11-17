package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/databaseguard/dbguard/internal/policy"
)

// myPacket wraps a payload in a MySQL packet header (3-byte LE len + seq).
func myPacket(seq byte, payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	out[0] = byte(len(payload))
	out[1] = byte(len(payload) >> 8)
	out[2] = byte(len(payload) >> 16)
	out[3] = seq
	copy(out[4:], payload)
	return out
}

// myHandshakeResponse builds a minimal HandshakeResponse41 with user + schema.
func myHandshakeResponse(user, db string) []byte {
	payload := make([]byte, 0, 64)
	// capability flags (LE): CLIENT_PROTOCOL_41 (0x200) | CLIENT_CONNECT_WITH_DB (0x8)
	caps := uint32(0x00000200 | 0x00000008)
	payload = append(payload, byte(caps), byte(caps>>8), byte(caps>>16), byte(caps>>24))
	// max packet size
	payload = append(payload, 0x00, 0x00, 0x00, 0x01)
	// charset
	payload = append(payload, 0x21)
	// 23 reserved bytes
	payload = append(payload, make([]byte, 23)...)
	// username NUL-terminated
	payload = append(payload, []byte(user)...)
	payload = append(payload, 0)
	// auth response: 1-byte length prefix = 0 (no auth data)
	payload = append(payload, 0)
	// database NUL-terminated
	payload = append(payload, []byte(db)...)
	payload = append(payload, 0)
	return myPacket(0, payload)
}

// myComQuery builds a COM_QUERY packet for the given SQL.
func myComQuery(sql string) []byte {
	payload := append([]byte{0x03}, []byte(sql)...)
	return myPacket(0, payload)
}

func TestProxyBlocksDeniedQueryInlineMySQL(t *testing.T) {
	// fake upstream DB
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

	// policy: deny any SQL referencing the "secrets" table, allow the rest
	eng := evalFunc(func(c *policy.Context) policy.Decision {
		if c.Engine != "mysql" {
			t.Errorf("expected engine mysql, got %q", c.Engine)
		}
		for _, tb := range c.Tables {
			if tb == "secrets" {
				return policy.Decision{Allowed: false, RuleIDs: []string{"block.secrets"}}
			}
		}
		return policy.Decision{Allowed: true}
	})

	p := New(Config{Listen: "127.0.0.1:0", Upstream: upLn.Addr().String(), Engine: "mysql"}, eng, nil, nil)
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

	// HandshakeResponse (first client packet) - forwarded, learns user/db
	cli.Write(myHandshakeResponse("app", "appdb"))
	time.Sleep(100 * time.Millisecond)
	select {
	case <-gotCh:
	case <-time.After(time.Second):
		t.Fatal("handshake not forwarded")
	}

	// 1) ALLOWED query must reach upstream
	cli.Write(myComQuery("SELECT id FROM customers"))
	select {
	case g := <-gotCh:
		if !contains(g, "SELECT id FROM customers") {
			t.Fatalf("allowed query not forwarded verbatim: %q", g)
		}
	case <-time.After(time.Second):
		t.Fatal("allowed query was NOT forwarded (should pass)")
	}

	// 2) DENIED query must NOT reach upstream; client gets an ERR packet
	cli.Write(myComQuery("SELECT * FROM secrets"))
	cli.SetReadDeadline(time.Now().Add(time.Second))
	resp := make([]byte, 1024)
	n, _ := cli.Read(resp)
	// ERR packet: 4-byte header, then 0xFF marker at payload[0] => resp[4]
	if n < 5 || resp[4] != 0xFF {
		t.Fatalf("expected MySQL ERR packet (0xFF), got %d bytes: %v", n, resp[:min(n, 8)])
	}
	if !contains(resp[:n], "blocked by policy") {
		t.Fatalf("error message missing policy text: %q", resp[:n])
	}
	select {
	case g := <-gotCh:
		if contains(g, "secrets") {
			t.Fatalf("DENIED query LEAKED to upstream: %q", g)
		}
	case <-time.After(300 * time.Millisecond):
		// good: nothing forwarded
	}
	t.Log("OK (mysql): allowed query forwarded; denied query blocked inline, never reached upstream")
}
