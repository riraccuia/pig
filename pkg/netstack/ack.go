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

// processAck is the ACK check of RFC 9293 §3.10.7.4. Acknowledgments are
// validated against sndMax because sndNxt is rewound after a timeout.
func (c *Conn) processAck(seg *segment) bool {
	if seqGT(seg.ack, c.sndMax) {
		c.sendAck()
		return false
	}
	dup := c.isDuplicateAck(seg)
	if seqGT(seg.ack, c.sndUna) {
		c.onNewAck(seg.ack)
	}
	if dup {
		c.onDuplicateAck()
	}
	c.updateSendWindow(seg)
	c.advanceCloseOnAck()
	return true
}

// isDuplicateAck follows the definition in RFC 5681 §2.
func (c *Conn) isDuplicateAck(seg *segment) bool {
	return c.sndNxt != c.sndUna &&
		seg.ack == c.sndUna &&
		len(seg.payload) == 0 &&
		!seg.hasAny(flagSYN|flagFIN) &&
		c.segmentWindow(seg) == c.sndWnd
}

func (c *Conn) segmentWindow(seg *segment) uint32 {
	return uint32(seg.window) << c.sndWscale
}

func (c *Conn) onNewAck(ack uint32) {
	acked := ack - c.sndUna
	c.sampleRTT(ack)
	c.discardAcked(ack)
	c.sndUna = ack
	if seqLT(c.sndNxt, ack) {
		c.sndNxt = ack
	}
	c.retries = 0
	if c.cc.onNewAck(acked, ack, c.flightSize()) {
		c.retransmitHead()
	}
	c.rearmRTO()
	c.cond.Broadcast()
}

// discardAcked frees acknowledged bytes; ack may also cover our FIN.
func (c *Conn) discardAcked(ack uint32) {
	dataEnd := c.sndBufSeq + uint32(c.sendBuf.Len())
	end := ack
	if seqGT(end, dataEnd) {
		end = dataEnd
	}
	if !seqGT(end, c.sndBufSeq) {
		return
	}
	c.sendBuf.Discard(int(end - c.sndBufSeq))
	c.sndBufSeq = end
}

func (c *Conn) onDuplicateAck() {
	if !c.cc.onDupAck(c.sndUna, c.sndMax, c.flightSize()) {
		return
	}
	c.stats.fastRetransmits++
	c.logger.Debugf("netstack: %s fast retransmit at seq %d", c.id, c.sndUna)
	c.retransmitHead()
}

// updateSendWindow applies the SND.WL1/SND.WL2 rule of RFC 9293 §3.10.7.4.
func (c *Conn) updateSendWindow(seg *segment) {
	if seqLT(seg.ack, c.sndUna) {
		return
	}
	newer := seqLT(c.sndWl1, seg.seq) || (c.sndWl1 == seg.seq && seqLE(c.sndWl2, seg.ack))
	if !newer {
		return
	}
	wasZero := c.sndWnd == 0
	c.sndWnd = c.segmentWindow(seg)
	c.sndWl1 = seg.seq
	c.sndWl2 = seg.ack
	if !wasZero || c.sndWnd == 0 {
		return
	}
	c.persistTimer.stop()
	c.persistBackoff = 0
}

// advanceCloseOnAck moves through the closing states once our FIN is acknowledged.
func (c *Conn) advanceCloseOnAck() {
	if !c.finSent || !seqGT(c.sndUna, c.finSeq) {
		return
	}
	switch c.state {
	case StateFinWait1:
		c.setState(StateFinWait2)
	case StateClosing:
		c.setState(StateTimeWait)
	case StateLastAck:
		c.closeWith(nil)
	}
}
