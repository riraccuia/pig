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

// Package netstack is a small userspace TCP stack for IPv4 and IPv6.
//
// A Stack exchanges raw IP datagrams through io.ReadWriteCloser: Read returns
// the next outbound datagram and Write accepts an inbound one. Connections are
// created with Dial and Listen and implement net.Conn and net.Listener.
package netstack

import (
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/common"
)

var _ io.ReadWriteCloser = (*Stack)(nil)

// Stack is a userspace TCP stack bound to one IPv4 and/or one IPv6 address.
type Stack struct {
	logger   common.Logger
	opts     Options
	local4   netip.Addr
	local6   netip.Addr
	wscale   uint8
	outbound *packetQueue
	issSeed  maphash.Seed
	start    time.Time

	mu         sync.Mutex
	conns      map[endpointID]*Conn
	listeners  map[uint16]*Listener
	udpSockets map[uint16]*UDPConn
	closed     atomic.Bool
}

// New creates a Stack. Either local address may be nil to disable that family.
func New(logger common.Logger, local4, local6 net.IP, opts Options) (*Stack, error) {
	if logger == nil {
		return nil, errors.New("netstack: logger is required")
	}
	addr4, err := parseLocalAddr(local4, true)
	if err != nil {
		return nil, err
	}
	addr6, err := parseLocalAddr(local6, false)
	if err != nil {
		return nil, err
	}
	if !addr4.IsValid() && !addr6.IsValid() {
		return nil, errors.New("netstack: at least one local address is required")
	}
	opts = opts.withDefaults()
	return &Stack{
		logger:     logger,
		opts:       opts,
		local4:     addr4,
		local6:     addr6,
		wscale:     opts.windowScaleShift(),
		outbound:   newPacketQueue(opts.OutboundQueueLen),
		issSeed:    maphash.MakeSeed(),
		start:      time.Now(),
		conns:      make(map[endpointID]*Conn),
		listeners:  make(map[uint16]*Listener),
		udpSockets: make(map[uint16]*UDPConn),
	}, nil
}

func parseLocalAddr(ip net.IP, want4 bool) (netip.Addr, error) {
	if ip == nil {
		return netip.Addr{}, nil
	}
	addr, ok := netip.AddrFromSlice(ip)
	addr = addr.Unmap()
	if !ok || addr.Is4() != want4 || addr.IsUnspecified() {
		return netip.Addr{}, fmt.Errorf("netstack: invalid local address %s", ip)
	}
	return addr, nil
}

func (s *Stack) SetReadDeadline(t time.Time) error {
	return s.outbound.setReadDeadline(t)
}

// Read blocks until an outbound IP datagram is available and copies it into p.
// It returns io.ErrShortBuffer, leaving the datagram queued, when p is too
// small, and io.EOF once the stack is closed.
func (s *Stack) Read(p []byte) (int, error) {
	return s.outbound.pop(p)
}

// Write delivers one inbound IP datagram. Datagrams that are malformed, carry
// neither TCP nor UDP, or are not addressed to this stack are dropped without error.
func (s *Stack) Write(p []byte) (int, error) {
	if s.isClosed() {
		return 0, net.ErrClosed
	}
	dg, err := parseDatagram(p)
	if err != nil {
		s.logger.Tracef("netstack: dropping datagram: %v", err)
		return len(p), nil
	}
	if !s.isLocal(dg.dst) {
		s.logger.Tracef("netstack: dropping datagram for non-local address %s", dg.dst)
		return len(p), nil
	}
	switch dg.proto {
	case protoTCP:
		s.inputTCP(dg)
	case protoUDP:
		s.inputUDP(dg)
	}
	return len(p), nil
}

func (s *Stack) inputTCP(dg datagram) {
	if s.opts.ChecksumValid != nil && !s.opts.ChecksumValid(protoTCP, dg.src, dg.dst, dg.payload) {
		s.logger.Debugf("netstack: dropping segment with bad checksum from %s", dg.src)
		return
	}
	seg, err := parseSegment(dg.payload)
	if err != nil {
		s.logger.Debugf("netstack: dropping segment from %s: %v", dg.src, err)
		return
	}
	id := endpointID{
		local:  netip.AddrPortFrom(dg.dst, seg.dstPort),
		remote: netip.AddrPortFrom(dg.src, seg.srcPort),
	}
	s.deliver(id, &seg)
}

// Close aborts every connection, listener and UDP socket and releases all resources.
func (s *Stack) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	s.mu.Lock()
	conns := make([]*Conn, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	listeners := make([]*Listener, 0, len(s.listeners))
	for _, l := range s.listeners {
		listeners = append(listeners, l)
	}
	sockets := make([]*UDPConn, 0, len(s.udpSockets))
	for _, u := range s.udpSockets {
		sockets = append(sockets, u)
	}
	s.mu.Unlock()

	for _, l := range listeners {
		l.Close()
	}
	for _, u := range sockets {
		u.Close()
	}
	for _, c := range conns {
		c.mu.Lock()
		c.closeWith(net.ErrClosed)
		c.mu.Unlock()
	}
	s.outbound.close()
	return nil
}

// Dial opens a TCP connection to raddr and waits for the handshake to finish.
func (s *Stack) Dial(ctx context.Context, raddr *net.TCPAddr) (net.Conn, error) {
	if raddr == nil {
		return nil, errors.New("netstack: remote address is required")
	}
	remote := raddr.AddrPort()
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	local, err := s.localFor(remote.Addr())
	if err != nil {
		return nil, err
	}
	c, err := s.newActiveConn(local, remote)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.connect()
	c.mu.Unlock()

	select {
	case <-c.ready:
	case <-ctx.Done():
		c.mu.Lock()
		c.abort(ctx.Err())
		c.mu.Unlock()
		return nil, ctx.Err()
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	if c.state == StateClosed {
		return nil, net.ErrClosed
	}
	return c, nil
}

// Listen accepts connections on laddr. A nil or unspecified IP matches every
// local address of either family.
func (s *Stack) Listen(laddr *net.TCPAddr) (net.Listener, error) {
	if laddr == nil || laddr.Port <= 0 || laddr.Port > 0xffff {
		return nil, errors.New("netstack: listen requires a port")
	}
	addr, _ := netip.AddrFromSlice(laddr.IP)
	addr = addr.Unmap()
	if addr.IsValid() && !addr.IsUnspecified() && !s.isLocal(addr) {
		return nil, fmt.Errorf("netstack: %s is not a local address", addr)
	}
	ap := netip.AddrPortFrom(addr, uint16(laddr.Port))

	if s.isClosed() { // fast path
		return nil, net.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed() {
		return nil, net.ErrClosed
	}
	if _, used := s.listeners[ap.Port()]; used {
		return nil, ErrAddressInUse
	}
	l := newListener(s, ap)
	s.listeners[ap.Port()] = l
	return l, nil
}

// ListenUDP opens a UDP socket on laddr. A nil or unspecified IP receives on
// every local address; port 0 picks an ephemeral port.
func (s *Stack) ListenUDP(laddr *net.UDPAddr) (*UDPConn, error) {
	var local netip.AddrPort
	if laddr != nil {
		if laddr.Port < 0 || laddr.Port > 0xffff {
			return nil, fmt.Errorf("netstack: invalid UDP port %d", laddr.Port)
		}
		addr, _ := netip.AddrFromSlice(laddr.IP)
		local = netip.AddrPortFrom(addr.Unmap(), uint16(laddr.Port))
	}
	addr := local.Addr()
	if addr.IsValid() && !addr.IsUnspecified() && !s.isLocal(addr) {
		return nil, fmt.Errorf("netstack: %s is not a local address", addr)
	}
	return s.bindUDP(local, netip.AddrPort{})
}

// DialUDP opens a UDP socket connected to raddr on an ephemeral port.
func (s *Stack) DialUDP(raddr *net.UDPAddr) (*UDPConn, error) {
	if raddr == nil || raddr.Port <= 0 || raddr.Port > 0xffff {
		return nil, errInvalidUDPAddr
	}
	remote := raddr.AddrPort()
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	local, err := s.localFor(remote.Addr())
	if err != nil {
		return nil, err
	}
	return s.bindUDP(netip.AddrPortFrom(local, 0), remote)
}

func (s *Stack) bindUDP(local, remote netip.AddrPort) (*UDPConn, error) {
	if s.isClosed() { // fast path
		return nil, net.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed() {
		return nil, net.ErrClosed
	}
	port := local.Port()
	if port == 0 {
		allocated, ok := allocatePort(func(port uint16) bool {
			_, used := s.udpSockets[port]
			return used
		})
		if !ok {
			return nil, ErrPortsExhausted
		}
		port = allocated
	}
	if _, used := s.udpSockets[port]; used {
		return nil, ErrAddressInUse
	}
	u := newUDPConn(s, netip.AddrPortFrom(local.Addr(), port), remote)
	s.udpSockets[port] = u
	return u, nil
}

func (s *Stack) lookupUDP(local netip.AddrPort) *UDPConn {
	s.mu.Lock()
	defer s.mu.Unlock()
	u := s.udpSockets[local.Port()]
	if u == nil || !u.accepts(local.Addr()) {
		return nil
	}
	return u
}

func (s *Stack) removeUDP(u *UDPConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.udpSockets[u.local.Port()] == u {
		delete(s.udpSockets, u.local.Port())
	}
}

// deliver routes a segment to its connection, a listener, or the CLOSED-state
// reset logic. It must be called without holding s.mu.
func (s *Stack) deliver(id endpointID, seg *segment) {
	if c := s.lookupConn(id); c != nil {
		c.mu.Lock()
		c.handleSegment(seg)
		c.mu.Unlock()
		return
	}
	l := s.lookupListener(id.local)
	if l != nil && seg.has(flagSYN) && !seg.hasAny(flagACK|flagRST) {
		l.handleSyn(id, seg)
		return
	}
	s.replyClosed(id, seg)
}

// replyClosed answers a segment for which no connection exists (RFC 9293 §3.10.7.1).
func (s *Stack) replyClosed(id endpointID, seg *segment) {
	if seg.has(flagRST) {
		return
	}
	rst := segment{srcPort: id.local.Port(), dstPort: id.remote.Port(), flags: flagRST}
	if seg.has(flagACK) {
		rst.seq = seg.ack
	}
	if !seg.has(flagACK) {
		rst.ack = seg.seq + seg.length()
		rst.flags |= flagACK
	}
	s.output(id, &rst)
}

func (s *Stack) output(id endpointID, seg *segment) {
	pkt := s.buildDatagram(id.local.Addr(), id.remote.Addr(), seg)
	if s.outbound.push(pkt) {
		return
	}
	s.logger.Debugf("netstack: outbound queue full or closed, dropping segment for %s", id)
}

func (s *Stack) newActiveConn(local netip.Addr, remote netip.AddrPort) (*Conn, error) {
	if s.isClosed() { // fast path
		return nil, net.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.isClosed() {
		return nil, net.ErrClosed
	}
	port, ok := allocatePort(func(port uint16) bool {
		return s.portBusy(endpointID{local: netip.AddrPortFrom(local, port), remote: remote})
	})
	if !ok {
		return nil, ErrPortsExhausted
	}
	id := endpointID{local: netip.AddrPortFrom(local, port), remote: remote}
	c := newConn(s, id, s.iss(id))
	s.conns[id] = c
	return c, nil
}

func (s *Stack) portBusy(id endpointID) bool {
	_, connected := s.conns[id]
	_, listening := s.listeners[id.local.Port()]
	return connected || listening
}

func (s *Stack) addConn(c *Conn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.conns[c.id]; exists || s.isClosed() {
		return false
	}
	s.conns[c.id] = c
	return true
}

func (s *Stack) removeConn(c *Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conns[c.id] == c {
		delete(s.conns, c.id)
	}
}

func (s *Stack) lookupConn(id endpointID) *Conn {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.conns[id]
}

func (s *Stack) lookupListener(local netip.AddrPort) *Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	l := s.listeners[local.Port()]
	if l == nil || !l.matches(local.Addr()) {
		return nil
	}
	return l
}

func (s *Stack) removeListener(l *Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listeners[l.addr.Port()] == l {
		delete(s.listeners, l.addr.Port())
	}
}

func (s *Stack) isClosed() bool {
	return s.closed.Load()
}

func (s *Stack) isLocal(addr netip.Addr) bool {
	return addr.IsValid() && (addr == s.local4 || addr == s.local6)
}

func (s *Stack) localFor(remote netip.Addr) (netip.Addr, error) {
	local := s.local6
	if remote.Is4() {
		local = s.local4
	}
	if !remote.IsValid() || !local.IsValid() {
		return netip.Addr{}, ErrNoLocalAddress
	}
	return local, nil
}

// iss derives the initial sequence number as recommended by RFC 6528: a
// 4-microsecond clock plus a keyed hash of the 4-tuple.
func (s *Stack) iss(id endpointID) uint32 {
	var h maphash.Hash
	h.SetSeed(s.issSeed)
	local, _ := id.local.MarshalBinary()
	remote, _ := id.remote.MarshalBinary()
	h.Write(local)
	h.Write(remote)
	ticks := uint32(time.Since(s.start) / (4 * time.Microsecond))
	return ticks + uint32(h.Sum64())
}
