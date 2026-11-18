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

// connect starts an active open (RFC 9293 §3.10.1).
func (c *Conn) connect() {
	c.setState(StateSynSent)
	c.sendSyn()
	c.armRTO()
}

func (c *Conn) sendSyn() {
	seg := c.newSegment(flagSYN, c.iss)
	seg.opts = c.synOptions()
	c.emitSyn(&seg)
}

func (c *Conn) sendSynAck() {
	seg := c.newSegment(flagSYN|flagACK, c.iss)
	seg.opts = c.synOptions()
	c.emitSyn(&seg)
}

func (c *Conn) emitSyn(seg *segment) {
	c.emit(seg)
	c.sndNxt = c.iss + 1
	c.sndMax = c.sndNxt
	if c.retries == 0 {
		c.startTiming(c.iss)
	}
}

func (c *Conn) retransmitSyn() {
	if c.state == StateSynSent {
		c.sendSyn()
		return
	}
	c.sendSynAck()
}

// synOptions advertises our MSS and, when enabled, our window scale. A SYN-ACK
// only carries window scale if the peer offered it (RFC 7323 §2.2).
func (c *Conn) synOptions() tcpOptions {
	return tcpOptions{
		mss:       uint16(min(c.localMSS, 0xffff)),
		hasMSS:    true,
		wscale:    c.rcvWscale,
		hasWScale: c.wsEnabled,
	}
}

// applyPeerOptions negotiates the send MSS (RFC 9293 §3.7.1, RFC 6691) and
// window scaling, which is only in effect when both sides sent the option.
func (c *Conn) applyPeerOptions(opts tcpOptions) {
	peerMSS := defaultPeerMSS(c.id.remote.Addr())
	if opts.hasMSS && opts.mss > 0 {
		peerMSS = uint32(opts.mss)
	}
	c.sendMSS = min(peerMSS, c.localMSS)
	c.cc.init(c.sendMSS, c.iss)
	if !c.wsEnabled || !opts.hasWScale {
		c.wsEnabled = false
		c.sndWscale = 0
		c.rcvWscale = 0
		return
	}
	if opts.wscale > maxWindowScale {
		c.logger.Debugf("netstack: %s peer window scale %d clamped to %d", c.id, opts.wscale, maxWindowScale)
	}
	c.sndWscale = min(opts.wscale, maxWindowScale)
}

// handleSynSent implements SYN-SENT processing (RFC 9293 §3.10.7.3).
func (c *Conn) handleSynSent(seg *segment) {
	if seg.has(flagACK) && (seqLE(seg.ack, c.iss) || seqGT(seg.ack, c.sndNxt)) {
		if !seg.has(flagRST) {
			c.sendRst(seg.ack)
		}
		return
	}
	ackOK := seg.has(flagACK)
	if seg.has(flagRST) {
		if ackOK {
			c.closeWith(ErrConnectionRefused)
		}
		return
	}
	if !seg.has(flagSYN) {
		return
	}
	c.irs = seg.seq
	c.rcvNxt = seg.seq + 1
	c.applyPeerOptions(seg.opts)
	// Windows in SYN segments are never scaled (RFC 7323 §2.2).
	c.sndWnd = uint32(seg.window)
	c.sndWl1 = seg.seq
	c.sndWl2 = seg.ack
	if !ackOK {
		c.setState(StateSynReceived)
		c.sendSynAck()
		return
	}
	c.sampleRTT(seg.ack)
	c.sndUna = seg.ack
	c.retries = 0
	c.rtoTimer.stop()
	c.setState(StateEstablished)
	c.sendAck()
	if len(seg.payload) == 0 && !seg.has(flagFIN) {
		return
	}
	seg.flags &^= flagSYN
	seg.seq++
	c.processSegment(seg)
}

// completePassiveOpen handles the ACK that moves SYN-RECEIVED to ESTABLISHED.
func (c *Conn) completePassiveOpen(seg *segment) bool {
	if !seqGT(seg.ack, c.sndUna) || seqGT(seg.ack, c.sndNxt) {
		c.sendRst(seg.ack)
		return false
	}
	c.sampleRTT(seg.ack)
	c.sndUna = seg.ack
	c.retries = 0
	c.rtoTimer.stop()
	c.sndWnd = c.segmentWindow(seg)
	c.sndWl1 = seg.seq
	c.sndWl2 = seg.ack
	c.setState(StateEstablished)
	return c.state == StateEstablished
}
