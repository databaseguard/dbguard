package ebpf

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/databaseguard/dbguard/internal/config"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewManagerMissingObjectDir(t *testing.T) {
	cfg := config.EBPFConfig{Enabled: true, ObjectDir: filepath.Join(t.TempDir(), "nope")}
	if _, err := NewManager(cfg, testLogger()); err == nil {
		t.Fatal("expected error for missing object dir")
	}

	// empty dir path with ebpf disabled degrades to a no-op manager
	cfg = config.EBPFConfig{Enabled: false}
	m, err := NewManager(cfg, testLogger())
	if err != nil {
		t.Fatalf("disabled manager should tolerate missing dir: %v", err)
	}
	if err := m.Start(context.Background(), nil); err != nil {
		t.Fatalf("disabled Start should be a no-op: %v", err)
	}
	if err := m.Close(); err != nil {
		t.Fatalf("disabled Close: %v", err)
	}
	// closed Events channel signals end of stream to consumers
	for range m.Events() {
		t.Fatal("no events expected")
	}
}

func TestParseLPMKey(t *testing.T) {
	cases := []struct {
		in      string
		want    lpmKey
		wantErr bool
	}{
		{in: "10.0.0.0/8", want: lpmKey{PrefixLen: 8, Addr: 0x0A000000}},
		{in: "10.8.3.4/32", want: lpmKey{PrefixLen: 32, Addr: 0x0A080304}},
		{in: "192.168.1.5", want: lpmKey{PrefixLen: 32, Addr: 0xC0A80105}}, // bare IP
		{in: "0.0.0.0/0", want: lpmKey{PrefixLen: 0, Addr: 0}},
		{in: "", wantErr: true},
		{in: "not-a-cidr", wantErr: true},
		{in: "2001:db8::/32", wantErr: true}, // IPv6 unsupported by the u32 key
		{in: "10.0.0.0/40", wantErr: true},   // prefix len beyond IPv4
	}
	for _, tc := range cases {
		got, err := parseLPMKey(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseLPMKey(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseLPMKey(%q): %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("parseLPMKey(%q) = %+v, want %+v", tc.in, got, tc.want)
		}
	}
}

// TestConfigMapLayout pins the wire layout of ConfigMap against the C
// struct dbg_config. encoding/binary writes fields packed (no internal
// padding): 2+2 bytes of ports plus 7 one-byte flags = 11 bytes. The C
// compiler additionally pads the struct tail to the 2-byte alignment of the
// uint16 members, so the kernel-side map value is 12 bytes - which matches
// Go's unsafe.Sizeof for the same struct, as required by cilium/ebpf's
// struct-marshalling Put.
func TestConfigMapLayout(t *testing.T) {
	cm := ConfigMap{
		PGPort: 5432, MySQLPort: 3306,
		SQLIEnabled: 1, DropEnabled: 1, PIIPrescan: 1,
		ExfilEnabled: 1, RIDSAlertOnly: 1, LineageEnabled: 1,
	}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, cm); err != nil {
		t.Fatal(err)
	}
	// The Go struct MUST marshal to exactly the kernel map's value_size.
	// The C dbg_config struct is 2*u16 + 6*u8 + pad[2] and aligns to 12
	// bytes; BTF reports value_size = 12. cilium/ebpf's Map.Put rejects any
	// value whose marshalled length != value_size, so a mismatch here means
	// every config_map write fails at runtime and the kernel programs run
	// with zeroed configuration. Keep this pinned at 12.
	if got, want := buf.Len(), 12; got != want {
		t.Fatalf("ConfigMap marshals to %d bytes, want %d (kernel config_map value_size)", got, want)
	}

	// roundtrip must reproduce every field
	var back ConfigMap
	if err := binary.Read(bytes.NewReader(buf.Bytes()), binary.LittleEndian, &back); err != nil {
		t.Fatal(err)
	}
	if back != cm {
		t.Fatalf("roundtrip mismatch: %+v != %+v", back, cm)
	}

	// spot-check the port encoding on the wire
	if got := binary.LittleEndian.Uint16(buf.Bytes()[0:2]); got != 5432 {
		t.Fatalf("PGPort wire = %d, want 5432", got)
	}
	if got := binary.LittleEndian.Uint16(buf.Bytes()[2:4]); got != 3306 {
		t.Fatalf("MySQLPort wire = %d, want 3306", got)
	}
}
