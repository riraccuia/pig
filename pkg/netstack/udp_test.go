// Copyright 2026 Riccardo Raccuia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netstack

import (
	"bytes"
	"errors"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/riraccuia/pig/pkg/network"
)

const udpTestPort = 5353

var udpFamilies = []struct {
	name     string
	serverIP net.IP
	server   netip.Addr
}{
	{"IPv4", serverIP4, netip.MustParseAddr("10.0.0.2")},
	{"IPv6", serverIP6, netip.MustParseAddr("fd00::2")},
}

func newUDPStack(t *testing.T, opts Options) *Stack {
	t.Helper()
	s, err := New(nopLogger{}, serverIP4, serverIP6, opts)
	if err != nil {
		t.Fatalf("stack: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// craftUDP builds an inbound IP datagram carrying payload from src to dst.
func craftUDP(s *Stack, src, dst netip.AddrPort, payload []byte) []byte {
	d := udpDatagram{srcPort: src.Port(), dstPort: dst.Port(), payload: payload}
	return s.buildDatagram(src.Addr(), dst.Addr(), &d)
}

func udpChecksumOffset(addr netip.Addr) int {
	return ipHeaderLen(addr) + 6
}

func queued(u *UDPConn) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.queue)
}

func readWithin(t *testing.T, u *UDPConn, p []byte) (int, net.Addr) {
	t.Helper()
	u.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, from, err := u.ReadFrom(p)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return n, from
}

func expectNoDatagram(t *testing.T, u *UDPConn) {
	t.Helper()
	u.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if _, _, err := u.ReadFrom(make([]byte, 1500)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read error = %v, want deadline exceeded", err)
	}
}

func TestUDPEcho(t *testing.T) {
	for _, family := range udpFamilies {
		t.Run(family.name, func(t *testing.T) {
			client, server := newStackPair(t, Options{}, Options{}, nil)
			srv, err := server.ListenUDP(&net.UDPAddr{Port: udpTestPort})
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			conn, err := client.DialUDP(&net.UDPAddr{IP: family.serverIP, Port: udpTestPort})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}

			if _, err := conn.Write([]byte("hello")); err != nil {
				t.Fatalf("write: %v", err)
			}
			buf := make([]byte, 1500)
			n, from := readWithin(t, srv, buf)
			if string(buf[:n]) != "hello" || from.String() != conn.LocalAddr().String() {
				t.Fatalf("server got %q from %s, want hello from %s", buf[:n], from, conn.LocalAddr())
			}
			if _, err := srv.WriteTo([]byte("world"), from); err != nil {
				t.Fatalf("write to: %v", err)
			}
			conn.SetReadDeadline(time.Now().Add(5 * time.Second))
			n, err = conn.Read(buf)
			if err != nil || string(buf[:n]) != "world" {
				t.Fatalf("client read = %q, %v; want world", buf[:n], err)
			}
		})
	}
}

func TestUDPMaxPayload(t *testing.T) {
	for _, family := range udpFamilies {
		t.Run(family.name, func(t *testing.T) {
			client, server := newStackPair(t, Options{}, Options{}, nil)
			srv, err := server.ListenUDP(&net.UDPAddr{Port: udpTestPort})
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			conn, err := client.DialUDP(&net.UDPAddr{IP: family.serverIP, Port: udpTestPort})
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			limit := defaultMTU - ipHeaderLen(family.server) - udpHeaderLen

			if _, err := conn.Write(make([]byte, limit+1)); !errors.Is(err, ErrMessageTooLong) {
				t.Fatalf("oversized write error = %v, want %v", err, ErrMessageTooLong)
			}
			payload := bytes.Repeat([]byte{0xa5}, limit)
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("write %d bytes: %v", limit, err)
			}
			buf := make([]byte, 2*limit)
			n, _ := readWithin(t, srv, buf)
			if !bytes.Equal(buf[:n], payload) {
				t.Fatalf("received %d bytes, want %d identical bytes", n, limit)
			}
		})
	}
}

func TestUDPTruncatesShortReadBuffer(t *testing.T) {
	s := newUDPStack(t, Options{})
	u, err := s.ListenUDP(&net.UDPAddr{Port: udpTestPort})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	src := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 40000)
	dst := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), udpTestPort)
	s.Write(craftUDP(s, src, dst, []byte("truncated")))
	s.Write(craftUDP(s, src, dst, []byte("next")))

	buf := make([]byte, 5)
	n, _ := readWithin(t, u, buf)
	if string(buf[:n]) != "trunc" {
		t.Fatalf("short read = %q, want trunc", buf[:n])
	}
	n, _ = readWithin(t, u, buf)
	if string(buf[:n]) != "next" {
		t.Fatalf("read after truncation = %q, want next", buf[:n])
	}
}

func TestUDPConnectedFiltersSource(t *testing.T) {
	client, server := newStackPair(t, Options{}, Options{}, nil)
	expected, err := server.ListenUDP(&net.UDPAddr{Port: udpTestPort})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	intruder, err := server.ListenUDP(&net.UDPAddr{Port: udpTestPort + 1})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	conn, err := client.DialUDP(&net.UDPAddr{IP: serverIP4, Port: udpTestPort})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	if _, err := intruder.WriteTo([]byte("intruder"), conn.LocalAddr()); err != nil {
		t.Fatalf("intruder write: %v", err)
	}
	if _, err := expected.WriteTo([]byte("expected"), conn.LocalAddr()); err != nil {
		t.Fatalf("expected write: %v", err)
	}
	buf := make([]byte, 1500)
	n, from := readWithin(t, conn, buf)
	if string(buf[:n]) != "expected" || from.String() != conn.RemoteAddr().String() {
		t.Fatalf("connected socket read %q from %s", buf[:n], from)
	}
	expectNoDatagram(t, conn)
}

func TestUDPReceiveBufferOverflow(t *testing.T) {
	const payloadLen = 100
	s := newUDPStack(t, Options{UDPRecvBufferSize: 3 * (udpHeaderLen + payloadLen)})
	u, err := s.ListenUDP(&net.UDPAddr{Port: udpTestPort})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	src := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 40000)
	dst := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), udpTestPort)
	for i := range 5 {
		s.Write(craftUDP(s, src, dst, bytes.Repeat([]byte{byte(i)}, payloadLen)))
	}
	if got := queued(u); got != 3 {
		t.Fatalf("queued %d datagrams, want 3", got)
	}
	buf := make([]byte, 1500)
	for i := range 3 {
		n, _ := readWithin(t, u, buf)
		if !bytes.Equal(buf[:n], bytes.Repeat([]byte{byte(i)}, payloadLen)) {
			t.Fatalf("datagram %d corrupted or out of order", i)
		}
	}
	expectNoDatagram(t, u)
}

// TestUDPChecksumHandling covers RFC 768 (IPv4 may omit the checksum) and
// RFC 8200 §8.1 (IPv6 requires it), plus corruption. Validation is opt-in
// via Options.ChecksumValid, so the off path is checked separately.
func TestUDPChecksumHandling(t *testing.T) {
	cases := []struct {
		name      string
		src, dst  string
		mutate    func(pkt []byte, src netip.Addr)
		delivered bool
	}{
		{"IPv4 valid", "10.0.0.1", "10.0.0.2", nil, true},
		{"IPv6 valid", "fd00::1", "fd00::2", nil, true},
		{"IPv4 zero checksum", "10.0.0.1", "10.0.0.2", zeroUDPChecksum, true},
		{"IPv6 zero checksum", "fd00::1", "fd00::2", zeroUDPChecksum, false},
		{"IPv4 corrupted", "10.0.0.1", "10.0.0.2", corruptLastByte, false},
		{"IPv6 corrupted", "fd00::1", "fd00::2", corruptLastByte, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertUDPDelivery(t, Options{ChecksumValid: network.TransportChecksumValid}, tc.src, tc.dst, tc.mutate, tc.delivered)
		})
	}
	t.Run("skipped when validation is off", func(t *testing.T) {
		assertUDPDelivery(t, Options{}, "fd00::1", "fd00::2", corruptLastByte, true)
		assertUDPDelivery(t, Options{}, "fd00::1", "fd00::2", zeroUDPChecksum, true)
	})
}

func assertUDPDelivery(t *testing.T, opts Options, srcAddr, dstAddr string, mutate func([]byte, netip.Addr), want bool) {
	t.Helper()
	s := newUDPStack(t, opts)
	u, err := s.ListenUDP(&net.UDPAddr{Port: udpTestPort})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	src := netip.AddrPortFrom(netip.MustParseAddr(srcAddr), 40000)
	dst := netip.AddrPortFrom(netip.MustParseAddr(dstAddr), udpTestPort)
	pkt := craftUDP(s, src, dst, []byte("checksum"))
	if mutate != nil {
		mutate(pkt, src.Addr())
	}
	if _, err := s.Write(pkt); err != nil {
		t.Fatalf("write: %v", err)
	}
	if got := queued(u) == 1; got != want {
		t.Fatalf("delivered = %v, want %v", got, want)
	}
}

func zeroUDPChecksum(pkt []byte, src netip.Addr) {
	off := udpChecksumOffset(src)
	pkt[off], pkt[off+1] = 0, 0
}

func corruptLastByte(pkt []byte, _ netip.Addr) {
	pkt[len(pkt)-1] ^= 0xff
}

func TestUDPDeadlineAndClose(t *testing.T) {
	s := newUDPStack(t, Options{})
	u, err := s.ListenUDP(&net.UDPAddr{Port: udpTestPort})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	expectNoDatagram(t, u)

	u.SetReadDeadline(time.Time{})
	readErr := make(chan error, 1)
	go func() {
		_, _, err := u.ReadFrom(make([]byte, 1500))
		readErr <- err
	}()
	time.Sleep(20 * time.Millisecond)
	if err := u.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	select {
	case err := <-readErr:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("blocked read error = %v, want %v", err, net.ErrClosed)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("close did not unblock the reader")
	}
	if err := u.Close(); err != nil {
		t.Fatalf("second close: %v", err)
	}
	if _, err := u.WriteTo([]byte("x"), &net.UDPAddr{IP: clientIP4, Port: 40000}); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("write after close = %v, want %v", err, net.ErrClosed)
	}
	again, err := s.ListenUDP(&net.UDPAddr{Port: udpTestPort})
	if err != nil {
		t.Fatalf("port not released after close: %v", err)
	}
	again.Close()
}

func TestUDPBinding(t *testing.T) {
	s := newUDPStack(t, Options{})
	u, err := s.ListenUDP(nil)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	if port := u.LocalAddr().(*net.UDPAddr).Port; port < ephemeralPortFirst {
		t.Fatalf("ephemeral port %d outside the RFC 6335 range", port)
	}
	if u.RemoteAddr() != nil {
		t.Fatal("unconnected socket reports a remote address")
	}
	if _, err := u.Write([]byte("x")); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("write on unconnected socket = %v, want %v", err, ErrNotConnected)
	}
	if _, err := s.ListenUDP(&net.UDPAddr{Port: u.LocalAddr().(*net.UDPAddr).Port}); !errors.Is(err, ErrAddressInUse) {
		t.Fatalf("duplicate bind = %v, want %v", err, ErrAddressInUse)
	}
	if _, err := s.ListenUDP(&net.UDPAddr{IP: net.ParseIP("192.0.2.1"), Port: udpTestPort}); err == nil {
		t.Fatal("bind to a non-local address succeeded")
	}

	bound4, err := s.ListenUDP(&net.UDPAddr{IP: serverIP4, Port: udpTestPort})
	if err != nil {
		t.Fatalf("listen on IPv4 address: %v", err)
	}
	if _, err := bound4.WriteTo([]byte("x"), &net.UDPAddr{IP: clientIP6, Port: 40000}); !errors.Is(err, ErrNoLocalAddress) {
		t.Fatalf("IPv6 write from IPv4-bound socket = %v, want %v", err, ErrNoLocalAddress)
	}
	src := netip.AddrPortFrom(netip.MustParseAddr("fd00::1"), 40000)
	dst := netip.AddrPortFrom(netip.MustParseAddr("fd00::2"), udpTestPort)
	s.Write(craftUDP(s, src, dst, []byte("other family")))
	if queued(bound4) != 0 {
		t.Fatal("IPv4-bound socket received an IPv6 datagram")
	}
}

func TestUDPStackClose(t *testing.T) {
	s, err := New(nopLogger{}, serverIP4, serverIP6, Options{})
	if err != nil {
		t.Fatalf("stack: %v", err)
	}
	u, err := s.ListenUDP(&net.UDPAddr{Port: udpTestPort})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	s.Close()
	if _, _, err := u.ReadFrom(make([]byte, 1500)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("read after stack close = %v, want %v", err, net.ErrClosed)
	}
	if _, err := s.ListenUDP(nil); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("listen after stack close = %v, want %v", err, net.ErrClosed)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.udpSockets) != 0 {
		t.Fatal("stack close left UDP sockets behind")
	}
}
