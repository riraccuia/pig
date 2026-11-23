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
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/riraccuia/pig/pkg/common"
)

var _ net.Conn = (*Conn)(nil)

// Conn is a TCP connection and its transmission control block. All fields
// below mu are guarded by it; inbound segments, timers and application calls
// all serialize on mu.
type Conn struct {
	stack    *Stack
	id       endpointID
	logger   common.Logger
	listener *Listener

	mu          sync.Mutex
	cond        *sync.Cond
	state       State
	err         error
	ready       chan struct{}
	readyClosed bool

	// Send sequence space (RFC 9293 §3.3.1). sndMax is the highest sequence
	// ever sent; it runs ahead of sndNxt after a retransmission timeout.
	// sendBuf holds unacknowledged and unsent data starting at sndBufSeq.
	iss       uint32
	sndUna    uint32
	sndNxt    uint32
	sndMax    uint32
	sndWnd    uint32
	sndWl1    uint32
	sndWl2    uint32
	sndWscale uint8
	sendMSS   uint32
	sendBuf   *ringBuffer
	sndBufSeq uint32
	finQueued bool
	finSent   bool
	finSeq    uint32

	// Receive sequence space.
	irs          uint32
	rcvNxt       uint32
	rcvWscale    uint8
	rcvAdvWnd    uint32
	rcvAdvEdge   uint32 // RCV.NXT + RCV.WND as last advertised
	recvBuf      *ringBuffer
	ooq          reassemblyQueue
	finReceived  bool
	unackedBytes int
	ack          ackStretch

	localMSS  uint32
	wsEnabled bool

	cc             newReno
	rtt            rttEstimator
	timing         rttTiming
	retries        int
	persistBackoff int

	rtoTimer      connTimer
	persistTimer  connTimer
	delAckTimer   connTimer
	timeWaitTimer connTimer
	finWait2Timer connTimer

	readClosed    bool
	writeClosed   bool
	readDeadline  deadline
	writeDeadline deadline

	stats connStats
}

type connStats struct {
	retransmits     uint64
	fastRetransmits uint64
	probes          uint64
}

func newConn(s *Stack, id endpointID, iss uint32) *Conn {
	c := &Conn{
		stack:     s,
		id:        id,
		logger:    s.logger.WithFields([]common.LoggerField{{Key: "tcp", Value: id.String()}}),
		ready:     make(chan struct{}),
		iss:       iss,
		sndUna:    iss,
		sndNxt:    iss,
		sndMax:    iss,
		sndBufSeq: iss + 1,
		sendBuf:   newRingBuffer(s.opts.SendBufferSize),
		recvBuf:   newRingBuffer(s.opts.RecvBufferSize),
		localMSS:  s.opts.localMSS(id.local.Addr()),
		wsEnabled: !s.opts.DisableWindowScale,
		rcvWscale: s.wscale,
		ack:       newAckStretch(),
		rtt:       newRTTEstimator(s.opts.MinRTO),
	}
	c.cond = sync.NewCond(&c.mu)
	c.sendMSS = c.localMSS
	c.cc.init(c.sendMSS, iss)
	return c
}

// State reports the current TCP state.
func (c *Conn) State() State {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.state
}

func (c *Conn) LocalAddr() net.Addr  { return net.TCPAddrFromAddrPort(c.id.local) }
func (c *Conn) RemoteAddr() net.Addr { return net.TCPAddrFromAddrPort(c.id.remote) }

func (c *Conn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		if c.readClosed {
			return 0, net.ErrClosed
		}
		if c.recvBuf.Len() > 0 {
			n := c.recvBuf.Read(p)
			c.maybeSendWindowUpdate()
			return n, nil
		}
		if c.err != nil {
			return 0, c.err
		}
		if c.finReceived || c.state == StateClosed {
			return 0, io.EOF
		}
		if c.readDeadline.exceeded() {
			return 0, os.ErrDeadlineExceeded
		}
		c.cond.Wait()
	}
}

func (c *Conn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	written := 0
	for written < len(p) {
		if err := c.writeError(); err != nil {
			return written, err
		}
		if c.writeDeadline.exceeded() {
			return written, os.ErrDeadlineExceeded
		}
		n := c.sendBuf.Write(p[written:])
		written += n
		if n > 0 {
			c.trySend()
			continue
		}
		c.cond.Wait()
	}
	return written, nil
}

func (c *Conn) writeError() error {
	if c.writeClosed {
		return net.ErrClosed
	}
	if c.err != nil {
		return c.err
	}
	if !c.state.canSendData() {
		return ErrNotConnected
	}
	return nil
}

func (c *Conn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline.set(c.cond, t)
	c.writeDeadline.set(c.cond, t)
	return nil
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline.set(c.cond, t)
	return nil
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writeDeadline.set(c.cond, t)
	return nil
}

func (c *Conn) setState(next State) {
	if c.state == next {
		return
	}
	c.logger.Debugf("netstack: %s -> %s", c.state, next)
	c.state = next
	c.cond.Broadcast()
	c.onStateEntered(next)
}

func (c *Conn) onStateEntered(s State) {
	switch s {
	case StateEstablished:
		c.onEstablished()
	case StateFinWait2:
		c.armOrphanTimeout()
	case StateTimeWait:
		c.rtoTimer.stop()
		c.persistTimer.stop()
		c.armTimeWait()
	case StateClosed:
		c.release()
	}
}

func (c *Conn) onEstablished() {
	c.signalReady()
	l := c.listener
	if l == nil {
		return
	}
	c.listener = nil
	if l.enqueue(c) {
		return
	}
	c.logger.Debugf("netstack: accept queue full, resetting")
	c.abort(ErrBacklogFull)
}

func (c *Conn) signalReady() {
	if c.readyClosed {
		return
	}
	c.readyClosed = true
	close(c.ready)
}
