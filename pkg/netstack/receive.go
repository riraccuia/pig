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

// processData handles segment text and FIN (RFC 9293 §3.10.7.4, seventh and
// eighth steps). Out-of-order segments are queued and, like segments that
// fill a gap, acknowledged immediately (RFC 5681 §4.2).
func (c *Conn) processData(seg *segment) {
	fin := seg.has(flagFIN)
	if len(seg.payload) == 0 && !fin {
		return
	}
	if !c.state.canReceiveData() {
		return
	}
	if seg.seq != c.rcvNxt {
		c.ooq.insert(seg.seq, seg.payload, fin)
		c.sendAck()
		return
	}
	filledGap := !c.ooq.empty()
	c.deliver(seg.payload)
	if fin {
		c.receiveFin()
		c.sendAck()
		return
	}
	if c.drainReassembly() || filledGap {
		c.sendAck()
		return
	}
	c.scheduleAck(len(seg.payload))
}

// deliver accepts in-order bytes. Data arriving after Close is acknowledged
// and discarded.
func (c *Conn) deliver(p []byte) {
	if len(p) == 0 {
		return
	}
	c.rcvNxt += uint32(len(p))
	c.cond.Broadcast()
	if c.readClosed {
		return
	}
	if n := c.recvBuf.Write(p); n < len(p) {
		c.logger.Errorf("netstack: %s receive buffer overflow, lost %d bytes", c.id, len(p)-n)
	}
}

// drainReassembly delivers queued segments that are now in order and reports
// whether a queued FIN was reached.
func (c *Conn) drainReassembly() bool {
	for {
		seg, ok := c.ooq.popReady(c.rcvNxt)
		if !ok {
			return false
		}
		c.deliver(seg.data)
		if seg.fin {
			c.receiveFin()
			return true
		}
	}
}

func (c *Conn) receiveFin() {
	c.rcvNxt++
	c.finReceived = true
	c.ooq.clear()
	c.cond.Broadcast()
	switch c.state {
	case StateEstablished:
		c.setState(StateCloseWait)
	case StateFinWait1:
		c.setState(StateClosing)
	case StateFinWait2:
		c.setState(StateTimeWait)
	}
}

// scheduleAck delays the ACK as allowed by RFC 9293 §3.8.6.3, but
// acknowledges at least every second full-sized segment.
func (c *Conn) scheduleAck(n int) {
	c.unackedBytes += n
	if c.unackedBytes >= 2*int(c.sendMSS) {
		c.sendAck()
		return
	}
	if c.delAckTimer.active {
		return
	}
	c.delAckTimer.arm(c, delayedAckTimeout, c.sendAck)
}
