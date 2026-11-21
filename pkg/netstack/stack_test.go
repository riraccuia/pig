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
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/network"
)

const (
	testPort    = 8080
	testTimeout = 60 * time.Second
)

var (
	clientIP4 = net.ParseIP("10.0.0.1")
	serverIP4 = net.ParseIP("10.0.0.2")
	clientIP6 = net.ParseIP("fd00::1")
	serverIP6 = net.ParseIP("fd00::2")
)

type nopLogger struct{}

func (nopLogger) WithFields([]common.LoggerField) common.Logger { return nopLogger{} }
func (nopLogger) SetLevel(string)                               {}
func (nopLogger) PrintLevel(string, ...any)                     {}
func (nopLogger) Info(...any)                                   {}
func (nopLogger) Infof(string, ...any)                          {}
func (nopLogger) Error(...any)                                  {}
func (nopLogger) Errorf(string, ...any)                         {}
func (nopLogger) Debug(...any)                                  {}
func (nopLogger) Debugf(string, ...any)                         {}
func (nopLogger) Fatal(...any)                                  {}
func (nopLogger) Fatalf(string, ...any)                         {}
func (nopLogger) Trace(...any)                                  {}
func (nopLogger) Tracef(string, ...any)                         {}
func (nopLogger) Flush()                                        {}

// dropFunc decides whether the i-th datagram in one direction is lost.
type dropFunc func(i int) bool

func dropEvery(n int) dropFunc {
	return func(i int) bool { return i > 0 && i%n == 0 }
}

// bridge copies datagrams from src to dst until src is closed.
func bridge(src, dst *Stack, drop dropFunc) {
	buf := make([]byte, 65536)
	for i := 0; ; i++ {
		n, err := src.Read(buf)
		if err != nil {
			return
		}
		if drop != nil && drop(i) {
			continue
		}
		if _, err := dst.Write(buf[:n]); err != nil {
			return
		}
	}
}

func newStackPair(t *testing.T, clientOpts, serverOpts Options, drop dropFunc) (*Stack, *Stack) {
	t.Helper()
	client, err := New(nopLogger{}, clientIP4, clientIP6, clientOpts)
	if err != nil {
		t.Fatalf("client stack: %v", err)
	}
	server, err := New(nopLogger{}, serverIP4, serverIP6, serverOpts)
	if err != nil {
		t.Fatalf("server stack: %v", err)
	}
	go bridge(client, server, drop)
	go bridge(server, client, drop)
	t.Cleanup(func() {
		client.Close()
		server.Close()
	})
	return client, server
}

// connect dials the server through the bridge and returns both endpoints.
func connect(t *testing.T, client, server *Stack, serverIP net.IP) (*Conn, *Conn) {
	t.Helper()
	ln, err := server.Listen(&net.TCPAddr{Port: testPort})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			close(accepted)
			return
		}
		accepted <- conn
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client.Dial(ctx, &net.TCPAddr{IP: serverIP, Port: testPort})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case serverConn, ok := <-accepted:
		if !ok {
			t.Fatal("accept failed")
		}
		return conn.(*Conn), serverConn.(*Conn)
	case <-time.After(10 * time.Second):
		t.Fatal("accept timed out")
	}
	return nil, nil
}

// sendRandom writes size pseudo-random bytes, half-closes, and returns their hash.
func sendRandom(conn *Conn, size int64, seed uint64) ([]byte, error) {
	var key [32]byte
	key[0] = byte(seed)
	src := io.LimitReader(rand.NewChaCha8(key), size)
	h := sha256.New()
	if _, err := io.Copy(io.MultiWriter(conn, h), src); err != nil {
		return nil, err
	}
	return h.Sum(nil), conn.CloseWrite()
}

type hashResult struct {
	sum []byte
	n   int64
	err error
}

func receiveHash(conn *Conn) <-chan hashResult {
	result := make(chan hashResult, 1)
	go func() {
		h := sha256.New()
		n, err := io.Copy(h, conn)
		result <- hashResult{sum: h.Sum(nil), n: n, err: err}
	}()
	return result
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func waitState(t *testing.T, c *Conn, want State) {
	t.Helper()
	waitFor(t, want.String(), func() bool { return c.State() == want })
}

func testTransfer(t *testing.T, serverIP net.IP, size int64, clientOpts, serverOpts Options, drop dropFunc) connStats {
	client, server := newStackPair(t, clientOpts, serverOpts, drop)
	clientConn, serverConn := connect(t, client, server, serverIP)
	received := receiveHash(serverConn)

	sent, err := sendRandom(clientConn, size, 1)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	select {
	case got := <-received:
		if got.err != nil {
			t.Fatalf("receive: %v", got.err)
		}
		if got.n != size {
			t.Fatalf("received %d bytes, want %d", got.n, size)
		}
		if !bytes.Equal(got.sum, sent) {
			t.Fatalf("SHA-256 mismatch: got %x want %x", got.sum, sent)
		}
	case <-time.After(testTimeout):
		t.Fatal("transfer timed out")
	}
	serverConn.Close()
	clientConn.Close()
	clientConn.mu.Lock()
	defer clientConn.mu.Unlock()
	return clientConn.stats
}

func TestTransfer10MiBIPv4(t *testing.T) {
	testTransfer(t, serverIP4, 10<<20, Options{}, Options{}, nil)
}

func TestTransfer10MiBIPv6(t *testing.T) {
	testTransfer(t, serverIP6, 10<<20, Options{}, Options{}, nil)
}

func TestTransferWithLoss(t *testing.T) {
	opts := Options{MinRTO: 20 * time.Millisecond}
	stats := testTransfer(t, serverIP4, 4<<20, opts, opts, dropEvery(53))
	if stats.fastRetransmits == 0 {
		t.Fatalf("no fast retransmits under loss: %+v", stats)
	}
	t.Logf("sender stats under loss: %+v", stats)
}

func TestTransferWithHeavyLoss(t *testing.T) {
	opts := Options{MinRTO: 20 * time.Millisecond}
	stats := testTransfer(t, serverIP6, 1<<20, opts, opts, dropEvery(7))
	if stats.retransmits <= stats.fastRetransmits {
		t.Fatalf("no retransmission timeouts under heavy loss: %+v", stats)
	}
	t.Logf("sender stats under heavy loss: %+v", stats)
}

func TestTransferHeldBackBySmallOutboundQueue(t *testing.T) {
	opts := Options{OutboundQueueLen: 16}
	stats := testTransfer(t, serverIP4, 4<<20, opts, opts, nil)
	if stats.retransmits != 0 {
		t.Fatalf("sender retransmitted on a lossless path: %+v", stats)
	}
}

func TestMSSNegotiation(t *testing.T) {
	client, server := newStackPair(t, Options{MSS: 1000}, Options{}, nil)
	clientConn, serverConn := connect(t, client, server, serverIP4)

	clientConn.mu.Lock()
	clientMSS := clientConn.sendMSS
	clientConn.mu.Unlock()
	serverConn.mu.Lock()
	serverMSS := serverConn.sendMSS
	serverConn.mu.Unlock()
	if clientMSS != 1000 || serverMSS != 1000 {
		t.Fatalf("send MSS client=%d server=%d, want 1000 for both", clientMSS, serverMSS)
	}
}

func TestMSSDefaultWithoutOption(t *testing.T) {
	stack, err := New(nopLogger{}, serverIP4, nil, Options{})
	if err != nil {
		t.Fatalf("stack: %v", err)
	}
	defer stack.Close()
	if _, err := stack.Listen(&net.TCPAddr{Port: testPort}); err != nil {
		t.Fatalf("listen: %v", err)
	}
	local := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), testPort)
	remote := netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 40000)
	syn := segment{srcPort: remote.Port(), dstPort: local.Port(), seq: 1000, flags: flagSYN, window: 0xffff}
	if _, err := stack.Write(stack.buildDatagram(remote.Addr(), local.Addr(), &syn)); err != nil {
		t.Fatalf("write SYN: %v", err)
	}

	buf := make([]byte, 1500)
	n, err := stack.Read(buf)
	if err != nil {
		t.Fatalf("read SYN-ACK: %v", err)
	}
	dg, err := parseDatagram(buf[:n])
	if err != nil {
		t.Fatalf("parse datagram: %v", err)
	}
	if !network.TransportChecksumValid(protoTCP, dg.src, dg.dst, dg.payload) {
		t.Fatal("SYN-ACK has an invalid checksum")
	}
	synAck, err := parseSegment(dg.payload)
	if err != nil {
		t.Fatalf("parse SYN-ACK: %v", err)
	}
	if !synAck.has(flagSYN|flagACK) || synAck.ack != 1001 {
		t.Fatalf("unexpected SYN-ACK flags=%#x ack=%d", synAck.flags, synAck.ack)
	}
	if !synAck.opts.hasMSS || synAck.opts.mss != 1460 {
		t.Fatalf("SYN-ACK MSS option = %+v, want 1460", synAck.opts)
	}
	if synAck.opts.hasWScale {
		t.Fatal("SYN-ACK carries window scale although the SYN did not offer it")
	}

	c := stack.lookupConn(endpointID{local: local, remote: remote})
	if c == nil {
		t.Fatal("no connection in SYN-RECEIVED")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.state != StateSynReceived {
		t.Fatalf("state = %s, want SYN-RECEIVED", c.state)
	}
	if c.sendMSS != defaultPeerMSS4 {
		t.Fatalf("send MSS = %d, want RFC 9293 default %d", c.sendMSS, defaultPeerMSS4)
	}
}

func TestWindowScaleNegotiation(t *testing.T) {
	client, server := newStackPair(t, Options{RecvBufferSize: 4 << 20}, Options{RecvBufferSize: 1 << 20}, nil)
	clientConn, serverConn := connect(t, client, server, serverIP6)

	clientConn.mu.Lock()
	defer clientConn.mu.Unlock()
	serverConn.mu.Lock()
	defer serverConn.mu.Unlock()
	if !clientConn.wsEnabled || !serverConn.wsEnabled {
		t.Fatal("window scaling not enabled on both sides")
	}
	if clientConn.rcvWscale != 7 || serverConn.rcvWscale != 5 {
		t.Fatalf("receive shifts client=%d server=%d, want 7 and 5", clientConn.rcvWscale, serverConn.rcvWscale)
	}
	if clientConn.sndWscale != serverConn.rcvWscale || serverConn.sndWscale != clientConn.rcvWscale {
		t.Fatal("send shift does not match the peer's receive shift")
	}
}

func TestWindowScaleDisabled(t *testing.T) {
	client, server := newStackPair(t, Options{DisableWindowScale: true}, Options{}, nil)
	clientConn, serverConn := connect(t, client, server, serverIP4)

	serverConn.mu.Lock()
	defer serverConn.mu.Unlock()
	if serverConn.wsEnabled || serverConn.sndWscale != 0 || serverConn.rcvWscale != 0 {
		t.Fatal("server scales windows although the client did not offer it")
	}
	clientConn.mu.Lock()
	defer clientConn.mu.Unlock()
	if clientConn.wsEnabled || clientConn.rcvWscale != 0 {
		t.Fatal("client scales windows although disabled")
	}
}

func TestZeroWindowProbe(t *testing.T) {
	const size = 1 << 20
	client, server := newStackPair(t, Options{MinRTO: 20 * time.Millisecond}, Options{RecvBufferSize: 64 << 10}, nil)
	clientConn, serverConn := connect(t, client, server, serverIP4)

	type sendResult struct {
		sum []byte
		err error
	}
	sent := make(chan sendResult, 1)
	go func() {
		sum, err := sendRandom(clientConn, size, 2)
		sent <- sendResult{sum: sum, err: err}
	}()

	waitFor(t, "zero window probes", func() bool {
		clientConn.mu.Lock()
		defer clientConn.mu.Unlock()
		return clientConn.sndWnd == 0 && clientConn.stats.probes >= 2
	})

	received := receiveHash(serverConn)
	var want sendResult
	select {
	case want = <-sent:
		if want.err != nil {
			t.Fatalf("send: %v", want.err)
		}
	case <-time.After(testTimeout):
		t.Fatal("sender stayed blocked after the window opened")
	}
	got := <-received
	if got.err != nil || got.n != size || !bytes.Equal(got.sum, want.sum) {
		t.Fatalf("received n=%d err=%v, hash match=%v", got.n, got.err, bytes.Equal(got.sum, want.sum))
	}
}

func TestStateTransitions(t *testing.T) {
	client, server := newStackPair(t, Options{MSL: 50 * time.Millisecond}, Options{}, nil)
	clientConn, serverConn := connect(t, client, server, serverIP4)
	waitState(t, clientConn, StateEstablished)
	waitState(t, serverConn, StateEstablished)

	if err := clientConn.CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}
	waitState(t, clientConn, StateFinWait2)
	if n, err := serverConn.Read(make([]byte, 1)); n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("server read = %d, %v; want EOF", n, err)
	}
	waitState(t, serverConn, StateCloseWait)

	if _, err := serverConn.Write([]byte("bye")); err != nil {
		t.Fatalf("write in CLOSE-WAIT: %v", err)
	}
	buf := make([]byte, 3)
	if _, err := io.ReadFull(clientConn, buf); err != nil || string(buf) != "bye" {
		t.Fatalf("read in FIN-WAIT-2 = %q, %v", buf, err)
	}

	serverConn.Close()
	waitState(t, serverConn, StateClosed)
	waitState(t, clientConn, StateTimeWait)
	waitState(t, clientConn, StateClosed)
	if c := client.lookupConn(clientConn.id); c != nil {
		t.Fatal("client connection still registered after TIME-WAIT")
	}
	if c := server.lookupConn(serverConn.id); c != nil {
		t.Fatal("server connection still registered after LAST-ACK")
	}
}

func TestSimultaneousCloseThroughClosing(t *testing.T) {
	client, server := newStackPair(t, Options{MSL: 50 * time.Millisecond}, Options{MSL: 50 * time.Millisecond}, nil)
	clientConn, serverConn := connect(t, client, server, serverIP4)

	clientConn.mu.Lock()
	serverConn.mu.Lock()
	clientConn.shutdownWrite()
	serverConn.shutdownWrite()
	serverConn.mu.Unlock()
	clientConn.mu.Unlock()

	waitState(t, clientConn, StateClosed)
	waitState(t, serverConn, StateClosed)
	for _, c := range []*Conn{clientConn, serverConn} {
		c.mu.Lock()
		err := c.err
		c.mu.Unlock()
		if err != nil {
			t.Fatalf("simultaneous close error on %s: %v", c.id, err)
		}
	}
}

func TestDialRefused(t *testing.T) {
	client, _ := newStackPair(t, Options{}, Options{}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := client.Dial(ctx, &net.TCPAddr{IP: serverIP4, Port: testPort})
	if !errors.Is(err, ErrConnectionRefused) {
		t.Fatalf("dial error = %v, want %v", err, ErrConnectionRefused)
	}
}

func TestResetOnAbort(t *testing.T) {
	client, server := newStackPair(t, Options{}, Options{}, nil)
	clientConn, serverConn := connect(t, client, server, serverIP4)

	clientConn.mu.Lock()
	clientConn.abort(net.ErrClosed)
	clientConn.mu.Unlock()

	waitState(t, serverConn, StateClosed)
	if _, err := serverConn.Read(make([]byte, 1)); !errors.Is(err, ErrConnectionReset) {
		t.Fatalf("server read error = %v, want %v", err, ErrConnectionReset)
	}
}

func TestReadDeadline(t *testing.T) {
	client, server := newStackPair(t, Options{}, Options{}, nil)
	clientConn, _ := connect(t, client, server, serverIP4)

	clientConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	_, err := clientConn.Read(make([]byte, 1))
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read error = %v, want deadline exceeded", err)
	}
}

func TestStackCloseTearsDown(t *testing.T) {
	client, server := newStackPair(t, Options{}, Options{}, nil)
	clientConn, _ := connect(t, client, server, serverIP4)

	client.Close()
	waitState(t, clientConn, StateClosed)
	if _, err := clientConn.Write([]byte("x")); err == nil {
		t.Fatal("write succeeded after stack close")
	}
	if _, err := client.Read(make([]byte, 1500)); !errors.Is(err, io.EOF) {
		t.Fatalf("stack read after close = %v, want EOF", err)
	}
	client.mu.Lock()
	defer client.mu.Unlock()
	if len(client.conns) != 0 || len(client.listeners) != 0 {
		t.Fatal("stack close left connections or listeners behind")
	}
}
