package adapter

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/riraccuia/pig/pkg/network"
)

// detachStdioIn stops the constructor stdin pump and frees both pipe FDs.
func detachStdioIn(a *StdioAdapter) {
	r := a.in.(*stdioReader)
	_ = r.pw.Close()
	_ = r.pr.Close()
}

func TestStdioAdapterDataIntegrity(t *testing.T) {
	bs := int(stdioBlockSize)

	cases := []struct {
		name string
		size int
	}{
		{"1x block", bs},
		{"2x block", 2 * bs},
		{"4x block", 4 * bs},
		{"8x block", 8 * bs},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			want := make([]byte, tc.size)
			if _, err := rand.Read(want); err != nil {
				t.Fatalf("rand.Read: %v", err)
			}

			sender, err := NewStdioAdapter(AdapterConfig{
				Address: []string{"100.64.0.1/32"},
			})
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := NewStdioAdapter(AdapterConfig{
				Address: []string{"100.64.0.1/30"},
			})
			if err != nil {
				t.Fatal(err)
			}

			inR, inW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			outR, outW, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}

			detachStdioIn(sender)
			detachStdioIn(receiver)
			sender.in = inR
			receiver.out = outW

			defer func() {
				_ = sender.Close()
				_ = receiver.Close()
				_ = outR.Close()
			}()

			go func() {
				_, _ = io.Copy(inW, bytes.NewReader(want))
				_ = inW.Close()
			}()

			var got bytes.Buffer
			collectDone := make(chan error, 1)
			go func() {
				_, copyErr := io.Copy(&got, outR)
				collectDone <- copyErr
			}()

			if _, err := io.Copy(receiver, sender); err != nil {
				t.Fatalf("bridge copy: %v", err)
			}
			_ = outW.Close()

			if err := <-collectDone; err != nil {
				t.Fatalf("collect stdout: %v", err)
			}

			if !bytes.Equal(got.Bytes(), want) {
				t.Fatalf("payload mismatch: got %d bytes, want %d", got.Len(), len(want))
			}
		})
	}
}

// Read must wrap stdin bytes in a fixed fake IPv4+UDP header so the rest of
// pig can treat stdio like a TUN packet. Layout: [20-byte IP | 8-byte UDP | payload].
func TestStdioAdapterWrapsStdinAsPacket(t *testing.T) {
	const input = "hello"
	wantDst := net.IPv4(100, 64, 0, 2)

	a, err := NewStdioAdapter(AdapterConfig{
		Address: []string{"100.64.0.1/30"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	detachStdioIn(a)
	a.in = inR

	go func() {
		_, _ = inW.Write([]byte(input))
		_ = inW.Close()
	}()

	wantLen := stdioHeaderLen + len(input)

	buf := make([]byte, a.BlockSize())
	n, err := a.Read(buf)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if n != wantLen {
		t.Fatalf("Read length: got %d, want %d", n, wantLen)
	}

	pkt := network.IPv4Packet(buf[:n])
	gotPayload := string(buf[stdioHeaderLen:n])

	if pkt.Version() != 4 || pkt.Protocol() != 17 {
		t.Fatalf("want IPv4/UDP, got version=%d protocol=%d", pkt.Version(), pkt.Protocol())
	}
	if pkt.TotalLength() != wantLen {
		t.Fatalf("IP total length: got %d, want %d", pkt.TotalLength(), wantLen)
	}
	if !pkt.SourceIP().Equal(net.IPv4zero) || !pkt.DestinationIP().Equal(wantDst) {
		t.Fatalf("addrs: got %s -> %s, want 0.0.0.0 -> %s",
			pkt.SourceIP(), pkt.DestinationIP(), wantDst)
	}
	if pkt.SourcePort() != stdioUDPPort || pkt.DestinationPort() != stdioUDPPort {
		t.Fatalf("UDP ports: got %d -> %d, want %d -> %d",
			pkt.SourcePort(), pkt.DestinationPort(), stdioUDPPort, stdioUDPPort)
	}
	if gotPayload != input {
		t.Fatalf("payload: got %q, want %q", gotPayload, input)
	}
}

func TestStdioAdapterReadDeadline(t *testing.T) {
	a, err := NewStdioAdapter(AdapterConfig{
		Address: []string{"100.64.0.1/32"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()

	// Keep *stdioReader (needed for SetReadDeadline) but point it at a fresh
	// quiet pipe instead of process stdin.
	r := a.in.(*stdioReader)
	_ = r.pw.Close()
	_ = r.pr.Close()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.pr, r.pw = pr, pw

	buf := make([]byte, a.BlockSize())

	// Past deadline on a quiet pipe should fail without destroying the reader.
	if err := a.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if _, err := a.Read(buf); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read: got %v, want os.ErrDeadlineExceeded", err)
	}

	// Clear deadline; a later write must still be readable.
	if err := a.SetReadDeadline(time.Time{}); err != nil {
		t.Fatalf("clear deadline: %v", err)
	}
	go func() {
		_, _ = pw.Write([]byte("after-deadline"))
	}()
	n, err := a.Read(buf)
	if err != nil {
		t.Fatalf("Read after clear: %v", err)
	}
	if got := buf[stdioHeaderLen:n]; string(got) != "after-deadline" {
		t.Fatalf("payload: got %q, want %q", got, "after-deadline")
	}
}
