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

func (c *Conn) newSegment(flags uint8, seq uint32) segment {
	seg := segment{
		srcPort: c.id.local.Port(),
		dstPort: c.id.remote.Port(),
		seq:     seq,
		flags:   flags,
		window:  c.windowField(flags&flagSYN != 0),
	}
	if flags&flagACK != 0 {
		seg.ack = c.rcvNxt
	}
	return seg
}

// windowField encodes the receive window, scaled per RFC 7323 §2.2 except
// in SYN segments.
func (c *Conn) windowField(syn bool) uint16 {
	free := c.rcvWindow()
	if syn {
		return uint16(min(free, maxWindowField))
	}
	return uint16(min(free>>c.rcvWscale, maxWindowField))
}

func (c *Conn) rcvWindow() uint32 {
	return uint32(c.recvBuf.Free())
}

// emit transmits seg. Any segment carrying an ACK satisfies a pending delayed ACK.
func (c *Conn) emit(seg *segment) {
	if seg.has(flagACK) {
		c.unackedBytes = 0
		c.delAckTimer.stop()
		c.rcvAdvWnd = c.advertisedBytes(seg)
	}
	c.stack.output(c.id, seg)
}

func (c *Conn) advertisedBytes(seg *segment) uint32 {
	if seg.has(flagSYN) {
		return uint32(seg.window)
	}
	return uint32(seg.window) << c.rcvWscale
}

func (c *Conn) sendAck() {
	if c.state == StateClosed || c.state == StateSynSent {
		return
	}
	seg := c.newSegment(flagACK, c.sndNxt)
	c.emit(&seg)
}

func (c *Conn) sendRst(seq uint32) {
	seg := segment{srcPort: c.id.local.Port(), dstPort: c.id.remote.Port(), seq: seq, flags: flagRST}
	c.stack.output(c.id, &seg)
}

// trySend transmits as much queued data as the windows allow, then the FIN
// once all data is out, and arms the persist timer if the peer window is closed.
func (c *Conn) trySend() {
	if !c.state.canTransmit() {
		return
	}
	for c.sendNextSegment() {
	}
	c.maybeSendFin()
	c.maybeArmPersist()
}

func (c *Conn) unsentBytes() int {
	return c.sendBuf.Len() - int(c.sndNxt-c.sndBufSeq)
}

func (c *Conn) sendNextSegment() bool {
	unsent := c.unsentBytes()
	if unsent <= 0 {
		return false
	}
	n := min(unsent, int(c.sendMSS), c.usableWindow())
	if n <= 0 {
		return false
	}
	// Sender-side silly window avoidance (RFC 9293 §3.8.6.2.1).
	if n < int(c.sendMSS) && n < unsent && c.sndNxt != c.sndUna {
		return false
	}
	payload := make([]byte, n)
	c.sendBuf.Peek(int(c.sndNxt-c.sndBufSeq), payload)
	flags := flagACK
	if n == unsent {
		flags |= flagPSH
	}
	seg := c.newSegment(flags, c.sndNxt)
	seg.payload = payload
	c.emit(&seg)
	c.onSent(uint32(n))
	return true
}

// onSent advances SND.NXT, times new data and starts the retransmission timer.
func (c *Conn) onSent(n uint32) {
	seq := c.sndNxt
	isNew := seqGE(seq, c.sndMax)
	c.sndNxt += n
	if seqGT(c.sndNxt, c.sndMax) {
		c.sndMax = c.sndNxt
	}
	if isNew {
		c.startTiming(seq)
	}
	if !c.rtoTimer.active {
		c.armRTO()
	}
}

func (c *Conn) maybeSendFin() {
	if !c.finQueued || c.finSent || c.unsentBytes() != 0 {
		return
	}
	seg := c.newSegment(flagFIN|flagACK, c.sndNxt)
	c.emit(&seg)
	c.finSeq = c.sndNxt
	c.finSent = true
	c.onSent(1)
}

// maybeSendWindowUpdate tells the peer about space freed by the application,
// applying receiver-side silly window avoidance (RFC 9293 §3.8.6.2.2).
func (c *Conn) maybeSendWindowUpdate() {
	if !c.state.canReceiveData() {
		return
	}
	wnd := uint32(c.windowField(false)) << c.rcvWscale
	if wnd <= c.rcvAdvWnd {
		return
	}
	if wnd-c.rcvAdvWnd < min(uint32(c.recvBuf.Cap()/2), c.sendMSS) {
		return
	}
	c.sendAck()
}
