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
	"errors"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"
)

var (
	_ net.PacketConn = (*UDPConn)(nil)
	_ net.Conn       = (*UDPConn)(nil)
)

var errInvalidUDPAddr = errors.New("netstack: invalid UDP address")

// UDPConn is a UDP socket bound to one local port. UDP is connectionless, so
// the socket is simply open until Close. A socket created by DialUDP is
// connected: it sends to its remote by default and drops datagrams from any
// other source.
type UDPConn struct {
	stack  *Stack
	local  netip.AddrPort
	remote netip.AddrPort

	mu            sync.Mutex
	cond          *sync.Cond
	queue         []udpPacket
	queueBytes    int
	closed        bool
	readDeadline  deadline
	writeDeadline deadline
}

type udpPacket struct {
	from netip.AddrPort
	data []byte
}

func newUDPConn(s *Stack, local, remote netip.AddrPort) *UDPConn {
	u := &UDPConn{stack: s, local: local, remote: remote}
	u.cond = sync.NewCond(&u.mu)
	return u
}

// ReadFrom returns the next datagram. A buffer shorter than the datagram
// receives a truncated copy and the remainder is discarded.
func (u *UDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, from, err := u.readFrom(p)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(from), nil
}

func (u *UDPConn) Read(p []byte) (int, error) {
	n, _, err := u.readFrom(p)
	return n, err
}

func (u *UDPConn) readFrom(p []byte) (int, netip.AddrPort, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	for len(u.queue) == 0 || u.closed {
		if u.closed {
			return 0, netip.AddrPort{}, net.ErrClosed
		}
		if u.readDeadline.exceeded() {
			return 0, netip.AddrPort{}, os.ErrDeadlineExceeded
		}
		u.cond.Wait()
	}
	pkt := u.queue[0]
	u.queue[0] = udpPacket{}
	u.queue = u.queue[1:]
	u.queueBytes -= udpHeaderLen + len(pkt.data)
	return copy(p, pkt.data), pkt.from, nil
}

func (u *UDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	to, ok := addr.(*net.UDPAddr)
	if !ok || to == nil {
		return 0, errInvalidUDPAddr
	}
	return u.writeTo(p, to.AddrPort())
}

// Write sends to the remote of a connected socket.
func (u *UDPConn) Write(p []byte) (int, error) {
	if !u.remote.IsValid() {
		return 0, ErrNotConnected
	}
	return u.writeTo(p, u.remote)
}

// writeTo never blocks: datagrams that do not fit in the outbound queue are
// dropped, as an interface queue would.
func (u *UDPConn) writeTo(p []byte, to netip.AddrPort) (int, error) {
	to = netip.AddrPortFrom(to.Addr().Unmap(), to.Port())
	if !to.Addr().IsValid() || to.Port() == 0 {
		return 0, errInvalidUDPAddr
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return 0, net.ErrClosed
	}
	if u.writeDeadline.exceeded() {
		return 0, os.ErrDeadlineExceeded
	}
	src, err := u.sourceFor(to.Addr())
	if err != nil {
		return 0, err
	}
	if len(p) > u.stack.opts.maxUDPPayload(to.Addr()) {
		return 0, ErrMessageTooLong
	}
	d := udpDatagram{srcPort: u.local.Port(), dstPort: to.Port(), payload: p}
	if !u.stack.outbound.push(buildDatagram(src, to.Addr(), &d)) {
		u.stack.logger.Debugf("netstack: outbound queue full or closed, dropping UDP datagram for %s", to)
	}
	return len(p), nil
}

// sourceFor picks the bound address, or the stack's address of dst's family
// when the socket is bound to every local address.
func (u *UDPConn) sourceFor(dst netip.Addr) (netip.Addr, error) {
	local := u.local.Addr()
	if !local.IsValid() || local.IsUnspecified() {
		return u.stack.localFor(dst)
	}
	if local.Is4() != dst.Is4() {
		return netip.Addr{}, ErrNoLocalAddress
	}
	return local, nil
}

// deliver queues an inbound datagram and reports false when it was dropped.
// The receive buffer accounts each datagram as header plus payload so that
// empty datagrams still consume space.
func (u *UDPConn) deliver(from netip.AddrPort, data []byte) bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed || (u.remote.IsValid() && from != u.remote) {
		return false
	}
	size := udpHeaderLen + len(data)
	if u.queueBytes+size > u.stack.opts.UDPRecvBufferSize {
		return false
	}
	u.queue = append(u.queue, udpPacket{from: from, data: append([]byte(nil), data...)})
	u.queueBytes += size
	u.cond.Broadcast()
	return true
}

// accepts reports whether the socket receives datagrams sent to local.
func (u *UDPConn) accepts(local netip.Addr) bool {
	addr := u.local.Addr()
	return !addr.IsValid() || addr.IsUnspecified() || addr == local
}

// Close releases the port and wakes blocked readers. It is idempotent.
func (u *UDPConn) Close() error {
	if u.markClosed() {
		u.stack.removeUDP(u)
	}
	return nil
}

func (u *UDPConn) markClosed() bool {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.closed {
		return false
	}
	u.closed = true
	u.queue = nil
	u.queueBytes = 0
	u.readDeadline.stop()
	u.writeDeadline.stop()
	u.cond.Broadcast()
	return true
}

func (u *UDPConn) LocalAddr() net.Addr {
	return net.UDPAddrFromAddrPort(u.local)
}

// RemoteAddr returns nil for sockets that are not connected.
func (u *UDPConn) RemoteAddr() net.Addr {
	if !u.remote.IsValid() {
		return nil
	}
	return net.UDPAddrFromAddrPort(u.remote)
}

func (u *UDPConn) SetDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.readDeadline.set(u.cond, t)
	u.writeDeadline.set(u.cond, t)
	return nil
}

func (u *UDPConn) SetReadDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.readDeadline.set(u.cond, t)
	return nil
}

func (u *UDPConn) SetWriteDeadline(t time.Time) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.writeDeadline.set(u.cond, t)
	return nil
}
