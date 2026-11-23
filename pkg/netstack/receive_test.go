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
	"net/netip"
	"testing"
	"time"
)

func TestAckThreshold(t *testing.T) {
	const mss = 1000
	cases := []struct {
		name      string
		segments  int
		advWindow uint32
		want      int
	}{
		{"starts at two segments", minAckStretch, 1 << 20, 2 * mss},
		{"follows the stretch", maxAckStretch, 1 << 20, maxAckStretch * mss},
		{"window caps the stretch at a quarter", maxAckStretch, 16 * mss, 4 * mss},
		{"small window keeps two segments", maxAckStretch, 2 * mss, 2 * mss},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := &Conn{localMSS: mss, rcvAdvWnd: tc.advWindow, ack: ackStretch{segments: tc.segments}}
			if got := c.ackThreshold(); got != tc.want {
				t.Fatalf("ackThreshold = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestAckStretchRampsAndResets(t *testing.T) {
	a := newAckStretch()
	for range 2 * maxAckStretch {
		a.grow()
	}
	if a.segments != maxAckStretch {
		t.Fatalf("stretch grew to %d, want at most %d", a.segments, maxAckStretch)
	}
	a.reset()
	if a.segments != minAckStretch || a.stretched() {
		t.Fatalf("stretch after reset = %d, want %d", a.segments, minAckStretch)
	}
}

func TestAckStretchDelay(t *testing.T) {
	cases := []struct {
		name string
		gap  time.Duration
		want time.Duration
	}{
		{"fast flow uses the minimum flush", 50 * time.Microsecond, minAckFlush},
		{"follows the arrival interval", 2 * time.Millisecond, ackPauseFactor * 2 * time.Millisecond},
		{"never exceeds the delayed-ACK timeout", 30 * time.Millisecond, delayedAckTimeout},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := ackStretch{segments: maxAckStretch, gap: tc.gap}
			if got := a.ackDelay(); got != tc.want {
				t.Fatalf("ackDelay = %v, want %v", got, tc.want)
			}
		})
	}
	minimum := newAckStretch()
	if got := minimum.ackDelay(); got != delayedAckTimeout {
		t.Fatalf("ackDelay at the minimum stretch = %v, want %v", got, delayedAckTimeout)
	}
}

func TestAckStretchIgnoresIdlePeriods(t *testing.T) {
	var a ackStretch
	start := time.Now()
	a.onArrival(start)
	a.onArrival(start.Add(time.Millisecond))
	a.onArrival(start.Add(time.Millisecond + time.Second))
	if a.gap != time.Millisecond {
		t.Fatalf("gap = %v after an idle second, want 1ms", a.gap)
	}
}

func TestAckWaitIsBoundedByTheDelayedAckTimeout(t *testing.T) {
	now := time.Now()
	a := ackStretch{
		segments: maxAckStretch,
		gap:      5 * time.Millisecond,
		last:     now,
		oldest:   now.Add(-delayedAckTimeout + time.Millisecond),
	}
	if got := a.ackWait(now); got != time.Millisecond {
		t.Fatalf("ackWait = %v, want the 1ms left of the delayed-ACK timeout", got)
	}
}

// newEstablishedConn returns a connection that accepts data at rcvNxt with
// the stretch at its maximum.
func newEstablishedConn(t *testing.T) *Conn {
	t.Helper()
	s := newUDPStack(t, Options{})
	id := endpointID{
		local:  netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), testPort),
		remote: netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 40000),
	}
	c := newConn(s, id, 1000)
	c.state = StateEstablished
	c.irs = 4999
	c.rcvNxt = 5000
	c.sndUna, c.sndNxt, c.sndMax = 1001, 1001, 1001
	c.sndWnd = 1 << 16
	c.ack.segments = maxAckStretch
	return c
}

func TestAckStretchSnapsBack(t *testing.T) {
	cases := []struct {
		name string
		seq  uint32
	}{
		{"on a sequence gap", 6000},
		{"on retransmitted data", 4900},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := newEstablishedConn(t)
			c.mu.Lock()
			defer c.mu.Unlock()
			c.handleSegment(&segment{seq: tc.seq, ack: 1001, flags: flagACK, window: 0xffff, payload: make([]byte, 200)})
			if c.ack.segments != minAckStretch {
				t.Fatalf("stretch = %d, want %d", c.ack.segments, minAckStretch)
			}
		})
	}

	t.Run("when the gap fills", func(t *testing.T) {
		c := newEstablishedConn(t)
		c.mu.Lock()
		defer c.mu.Unlock()
		c.handleSegment(&segment{seq: 5100, ack: 1001, flags: flagACK, window: 0xffff, payload: make([]byte, 100)})
		c.ack.segments = maxAckStretch
		c.handleSegment(&segment{seq: 5000, ack: 1001, flags: flagACK, window: 0xffff, payload: make([]byte, 100)})
		if c.ack.segments != minAckStretch || c.rcvNxt != 5200 {
			t.Fatalf("stretch = %d, rcvNxt = %d; want %d and 5200", c.ack.segments, c.rcvNxt, minAckStretch)
		}
	})

	t.Run("on a pause", func(t *testing.T) {
		c := newEstablishedConn(t)
		c.mu.Lock()
		c.handleSegment(&segment{seq: 5000, ack: 1001, flags: flagACK, window: 0xffff, payload: make([]byte, 100)})
		c.mu.Unlock()
		waitFor(t, "stretch to reset after a pause", func() bool {
			c.mu.Lock()
			defer c.mu.Unlock()
			return c.ack.segments == minAckStretch && c.unackedBytes == 0
		})
	})
}

func TestDuplicateAcksKeepTheirWindow(t *testing.T) {
	c := newEstablishedConn(t)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sendAck()
	c.handleSegment(&segment{seq: 5000, ack: 1001, flags: flagACK, window: 0xffff, payload: make([]byte, 1000)})
	c.handleSegment(&segment{seq: 7000, ack: 1001, flags: flagACK, window: 0xffff, payload: make([]byte, 500)})
	first := c.windowField(false)

	c.recvBuf.Read(make([]byte, 300))
	c.maybeSendWindowUpdate()
	c.handleSegment(&segment{seq: 8000, ack: 1001, flags: flagACK, window: 0xffff, payload: make([]byte, 500)})
	if got := c.windowField(false); got != first {
		t.Fatalf("duplicate ACK window changed from %d to %d after a small read", first, got)
	}
}

func TestWindowReopensAfterAnMSS(t *testing.T) {
	c := newEstablishedConn(t)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recvBuf = newRingBuffer(maxWindowField)
	c.rcvWscale = 0
	c.sendAck()
	mss := int(c.sendMSS)
	c.handleSegment(&segment{seq: 5000, ack: 1001, flags: flagACK, window: 0xffff, payload: make([]byte, 2*mss)})
	c.sendAck()
	edge := c.rcvAdvEdge

	c.recvBuf.Read(make([]byte, mss-1))
	c.maybeSendWindowUpdate()
	if c.rcvAdvEdge != edge {
		t.Fatalf("right edge moved by %d after freeing less than an MSS", c.rcvAdvEdge-edge)
	}

	c.recvBuf.Read(make([]byte, 1))
	c.maybeSendWindowUpdate()
	if c.rcvAdvEdge-edge != uint32(mss) {
		t.Fatalf("right edge moved by %d after freeing an MSS, want %d", c.rcvAdvEdge-edge, mss)
	}
}

func TestRightEdgeHeldWhileReassembling(t *testing.T) {
	c := newEstablishedConn(t)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.recvBuf = newRingBuffer(maxWindowField)
	c.rcvWscale = 0
	c.sendAck()
	mss := uint32(c.sendMSS)
	c.handleSegment(&segment{seq: 5000, ack: 1001, flags: flagACK, window: 0xffff, payload: make([]byte, 2*mss)})
	c.handleSegment(&segment{seq: 5000 + 3*mss, ack: 1001, flags: flagACK, window: 0xffff, payload: make([]byte, mss)})
	edge := c.rcvAdvEdge

	c.recvBuf.Read(make([]byte, 2*mss))
	c.maybeSendWindowUpdate()
	if c.rcvAdvEdge != edge {
		t.Fatalf("right edge moved by %d while a gap was open", c.rcvAdvEdge-edge)
	}

	c.handleSegment(&segment{seq: 5000 + 2*mss, ack: 1001, flags: flagACK, window: 0xffff, payload: make([]byte, mss)})
	if c.rcvAdvEdge-edge != 2*mss {
		t.Fatalf("right edge moved by %d after the gap filled, want %d", c.rcvAdvEdge-edge, 2*mss)
	}
}

// TestGapFillDeliversQueuedData queues, in reverse order, segments covering the
// whole receive window and beyond it, then fills the leading gap: exactly the
// window must be delivered, in order, with nothing left queued.
func TestGapFillDeliversQueuedData(t *testing.T) {
	c := newEstablishedConn(t)
	c.mu.Lock()
	defer c.mu.Unlock()
	mss := int(c.localMSS)
	window := int(c.rcvWindow())
	base := c.rcvNxt
	stream := make([]byte, window+2*mss)
	for i := range stream {
		stream[i] = byte(i % 251)
	}
	segmentAt := func(off int) *segment {
		return &segment{seq: base + uint32(off), ack: 1001, flags: flagACK, window: 0xffff, payload: stream[off : off+mss]}
	}

	for off := (len(stream) - mss) / mss * mss; off >= mss; off -= mss {
		c.handleSegment(segmentAt(off))
	}
	if c.rcvNxt != base {
		t.Fatalf("rcvNxt moved by %d before the gap was filled", c.rcvNxt-base)
	}

	c.handleSegment(segmentAt(0))
	if got := int(c.rcvNxt - base); got != window || !c.ooq.empty() {
		t.Fatalf("delivered %d bytes, reassembly empty %t; want %d and true", got, c.ooq.empty(), window)
	}
	if c.rcvWindow() != 0 {
		t.Fatalf("receive window = %d after filling it, want 0", c.rcvWindow())
	}
	got := make([]byte, window)
	if n := c.recvBuf.Read(got); n != window || !bytes.Equal(got, stream[:window]) {
		t.Fatalf("read %d bytes, content matches %t; want %d and true", n, bytes.Equal(got, stream[:window]), window)
	}
}

func TestAckStretchRampsOnThresholdAcks(t *testing.T) {
	c := newEstablishedConn(t)
	c.ack.segments = minAckStretch
	c.mu.Lock()
	defer c.mu.Unlock()
	mss := int(c.localMSS)
	seq := c.rcvNxt
	for range minAckStretch {
		c.handleSegment(&segment{seq: seq, ack: 1001, flags: flagACK, window: 0xffff, payload: make([]byte, mss)})
		seq += uint32(mss)
	}
	if c.ack.segments != minAckStretch+1 || c.unackedBytes != 0 {
		t.Fatalf("after a threshold ACK: stretch %d, unacked %d; want %d and 0", c.ack.segments, c.unackedBytes, minAckStretch+1)
	}
}
