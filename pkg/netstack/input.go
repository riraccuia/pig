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

func (c *Conn) handleSegment(seg *segment) {
	switch c.state {
	case StateClosed:
		return
	case StateSynSent:
		c.handleSynSent(seg)
		return
	}
	c.processSegment(seg)
}

// processSegment implements RFC 9293 §3.10.7.4 for every state after SYN-SENT.
func (c *Conn) processSegment(seg *segment) {
	if c.isRetransmission(seg) {
		c.ack.reset()
	}
	if !c.acceptable(seg) && !c.acceptZeroWindowAck(seg) {
		c.rejectSegment(seg)
		return
	}
	c.trimFront(seg)
	c.trimTail(seg)
	if seg.has(flagRST) {
		c.handleRst(seg)
		return
	}
	if seg.has(flagSYN) {
		// An in-window SYN draws a challenge ACK (RFC 5961 §4.2).
		c.sendAck()
		return
	}
	if !seg.has(flagACK) {
		return
	}
	if c.state == StateSynReceived && !c.completePassiveOpen(seg) {
		return
	}
	if !c.processAck(seg) || c.state == StateClosed {
		return
	}
	c.processData(seg)
	c.trySend()
}

// acceptable is the segment acceptability test of RFC 9293 §3.10.7.4.
func (c *Conn) acceptable(seg *segment) bool {
	segLen := seg.length()
	wnd := c.rcvWindow()
	if segLen == 0 && wnd == 0 {
		return seg.seq == c.rcvNxt
	}
	if segLen == 0 {
		return c.inWindow(seg.seq, wnd)
	}
	if wnd == 0 {
		return false
	}
	return c.inWindow(seg.seq, wnd) || c.inWindow(seg.seq+segLen-1, wnd)
}

func (c *Conn) inWindow(seq, wnd uint32) bool {
	return seqGE(seq, c.rcvNxt) && seqLT(seq, c.rcvNxt+wnd)
}

// acceptZeroWindowAck keeps the ACK of a data segment that arrived while our
// window is zero; RFC 9293 §3.10.7.4 requires valid ACKs to be processed.
func (c *Conn) acceptZeroWindowAck(seg *segment) bool {
	if c.rcvWindow() != 0 || seg.seq != c.rcvNxt || !seg.has(flagACK) || seg.hasAny(flagRST|flagSYN) {
		return false
	}
	seg.payload = nil
	seg.flags &^= flagFIN
	c.sendAck()
	return true
}

// rejectSegment answers an unacceptable segment with an ACK. This is also how
// zero-window probes are answered.
func (c *Conn) rejectSegment(seg *segment) {
	if seg.has(flagRST) {
		return
	}
	if c.state == StateTimeWait && seg.has(flagFIN) {
		c.armTimeWait()
	}
	c.sendAck()
}

// trimFront drops the part of seg that precedes RCV.NXT.
func (c *Conn) trimFront(seg *segment) {
	if !seqLT(seg.seq, c.rcvNxt) {
		return
	}
	if seg.has(flagSYN) {
		seg.flags &^= flagSYN
		seg.seq++
	}
	skip := int(c.rcvNxt - seg.seq)
	if skip > len(seg.payload) {
		seg.payload = nil
		seg.flags &^= flagFIN
		seg.seq = c.rcvNxt
		return
	}
	seg.payload = seg.payload[skip:]
	seg.seq = c.rcvNxt
}

// trimTail drops the part of seg beyond the receive window.
func (c *Conn) trimTail(seg *segment) {
	limit := c.rcvNxt + c.rcvWindow()
	end := seg.seq + uint32(len(seg.payload))
	if !seqGT(end, limit) {
		return
	}
	keep := max(int(int32(limit-seg.seq)), 0)
	seg.payload = seg.payload[:min(keep, len(seg.payload))]
	seg.flags &^= flagFIN
}

// handleRst validates a reset per RFC 9293 §3.10.7.4 and RFC 5961 §3.2.
func (c *Conn) handleRst(seg *segment) {
	if seg.seq != c.rcvNxt {
		c.sendAck()
		return
	}
	switch c.state {
	case StateSynReceived:
		if c.listener != nil {
			c.closeWith(nil)
			return
		}
		c.closeWith(ErrConnectionRefused)
	case StateClosing, StateLastAck, StateTimeWait:
		c.closeWith(nil)
	default:
		c.closeWith(ErrConnectionReset)
	}
}
