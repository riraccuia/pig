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
	"net"
	"net/netip"
	"sync"
)

var _ net.Listener = (*Listener)(nil)

// Listener is a passive TCP endpoint. Connections become available to
// Accept once their handshake completes.
type Listener struct {
	stack     *Stack
	addr      netip.AddrPort
	accept    chan *Conn
	done      chan struct{}
	closeOnce sync.Once
}

func newListener(s *Stack, addr netip.AddrPort) *Listener {
	return &Listener{
		stack:  s,
		addr:   addr,
		accept: make(chan *Conn, s.opts.Backlog),
		done:   make(chan struct{}),
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case c := <-l.accept:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

// Close stops listening and resets connections that were never accepted.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() {
		close(l.done)
		l.stack.removeListener(l)
		l.drain()
	})
	return nil
}

func (l *Listener) Addr() net.Addr {
	return net.TCPAddrFromAddrPort(l.addr)
}

func (l *Listener) drain() {
	for {
		select {
		case c := <-l.accept:
			c.mu.Lock()
			c.abort(net.ErrClosed)
			c.mu.Unlock()
		default:
			return
		}
	}
}

func (l *Listener) matches(local netip.Addr) bool {
	addr := l.addr.Addr()
	return !addr.IsValid() || addr.IsUnspecified() || addr == local
}

// enqueue hands an established connection to Accept without blocking.
func (l *Listener) enqueue(c *Conn) bool {
	select {
	case <-l.done:
		return false
	default:
	}
	select {
	case l.accept <- c:
		return true
	default:
		return false
	}
}

// handleSyn performs the LISTEN-state SYN processing of RFC 9293 §3.10.7.2.
func (l *Listener) handleSyn(id endpointID, seg *segment) {
	c := newConn(l.stack, id, l.stack.iss(id))
	c.mu.Lock()
	defer c.mu.Unlock()
	if !l.stack.addConn(c) {
		return
	}
	c.listener = l
	c.irs = seg.seq
	c.rcvNxt = seg.seq + 1
	c.applyPeerOptions(seg.opts)
	c.sndWnd = uint32(seg.window)
	c.sndWl1 = seg.seq
	c.setState(StateSynReceived)
	c.sendSynAck()
	c.armRTO()
}
