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

package wireguard

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/transport"
	"golang.zx2c4.com/wireguard/device"
)

// Conn is a transport.Conn over a wireguard-go device and fake TUN.
//
// Write pushes one plaintext IP packet into the device (encrypt → UDP).
// Read pops one decrypted IP packet from the device (UDP → decrypt).
// Callers that batch packets (e.g. client flushBatchAsPackets) must split
// before Write; this method treats b as a single datagram.
//
// Both directions borrow buffers synchronously: Write does not return until
// the device has copied b; Read copies into the caller before releasing the
// device buffer.
type Conn struct {
	dev        *device.Device
	tun        *fakeTUN
	localAddr  net.Addr
	remoteAddr net.Addr
	closeOnce  sync.Once

	// Set for listener's pion udp.Conn; dial path leaves this nil.
	underlyingConn net.Conn

	readDeadline  atomic.Value // time.Time
	writeDeadline atomic.Value // time.Time
}

func (c *Conn) IsStreamed() bool { return false }

// AtomicPacketWrites reports that each Write must carry one IP packet.
func (c *Conn) AtomicPacketWrites() bool { return true }

func (c *Conn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *Conn) NewStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *Conn) LocalAddr() net.Addr  { return c.localAddr }
func (c *Conn) RemoteAddr() net.Addr { return c.remoteAddr }

func (c *Conn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}

func (c *Conn) Write(b []byte) (int, error) {
	if err := waitChanSend(c.tun.outbound, b, c.tun.closed, loadTime(c.writeDeadline)); err != nil {
		return 0, err
	}
	if err := waitAck(c.tun.outAck, c.tun.closed); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *Conn) Read(b []byte) (int, error) {
	pkt, err := waitChanRecv(c.tun.inbound, c.tun.closed, loadTime(c.readDeadline))
	if err != nil {
		return 0, err
	}
	if len(b) < len(pkt) {
		c.ackInbound()
		return 0, io.ErrShortBuffer
	}
	n := copy(b, pkt)
	c.ackInbound()
	return n, nil
}

func (c *Conn) Close() error {
	c.closeOnce.Do(func() {
		if c.underlyingConn != nil {
			_ = c.underlyingConn.Close()
		}
		_ = c.tun.Close()
		if c.dev != nil {
			c.dev.Close()
		}
	})
	return nil
}

func (c *Conn) String() string {
	return fmt.Sprintf("wg(%s<->%s)", c.localAddr, c.remoteAddr)
}

func (c *Conn) ackInbound() {
	select {
	case <-c.tun.closed:
	case c.tun.inAck <- struct{}{}:
	}
}

func loadTime(v atomic.Value) time.Time {
	if x := v.Load(); x != nil {
		return x.(time.Time)
	}
	return time.Time{}
}

func waitAck(ack <-chan struct{}, closed <-chan struct{}) error {
	select {
	case <-closed:
		return net.ErrClosed
	case <-ack:
		return nil
	}
}

func waitChanSend(ch chan<- []byte, pkt []byte, closed <-chan struct{}, deadline time.Time) error {
	if deadline.IsZero() {
		select {
		case <-closed:
			return net.ErrClosed
		case ch <- pkt:
			return nil
		}
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-closed:
		return net.ErrClosed
	case ch <- pkt:
		return nil
	case <-timer.C:
		return os.ErrDeadlineExceeded
	}
}

func waitChanRecv(ch <-chan []byte, closed <-chan struct{}, deadline time.Time) ([]byte, error) {
	if deadline.IsZero() {
		select {
		case <-closed:
			return nil, net.ErrClosed
		case pkt := <-ch:
			return pkt, nil
		}
	}
	timer := time.NewTimer(time.Until(deadline))
	defer timer.Stop()
	select {
	case <-closed:
		return nil, net.ErrClosed
	case pkt := <-ch:
		return pkt, nil
	case <-timer.C:
		return nil, os.ErrDeadlineExceeded
	}
}
