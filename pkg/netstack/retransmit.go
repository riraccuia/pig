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

import "time"

func (c *Conn) armRTO() {
	c.rtoTimer.arm(c, c.rtt.rto, c.onRTO)
}

// rearmRTO restarts the timer while data is outstanding (RFC 6298 §5.2, §5.3).
func (c *Conn) rearmRTO() {
	if c.sndNxt == c.sndUna {
		c.rtoTimer.stop()
		return
	}
	c.armRTO()
}

// onRTO handles a retransmission timeout (RFC 6298 §5.4-5.6, RFC 5681 §3.1).
// Transmission restarts from SND.UNA under a one-segment window.
func (c *Conn) onRTO() {
	c.retries++
	c.rtt.backoff()
	c.timing.active = false
	c.stats.retransmits++
	if c.state == StateSynSent || c.state == StateSynReceived {
		c.onHandshakeTimeout()
		return
	}
	if c.sndNxt == c.sndUna {
		return
	}
	if c.retries > maxDataRetries {
		c.abort(ErrTimeout)
		return
	}
	c.logger.Debugf("netstack: %s retransmission timeout at seq %d, rto %v", c.id, c.sndUna, c.rtt.rto)
	c.cc.onRTO(c.flightSize(), c.sndMax)
	c.sndNxt = c.sndUna
	if c.finSent && !seqGT(c.sndUna, c.finSeq) {
		c.finSent = false
	}
	c.trySend()
}

func (c *Conn) onHandshakeTimeout() {
	if c.retries > maxSynRetries {
		c.closeWith(ErrTimeout)
		return
	}
	c.logger.Debugf("netstack: %s retransmitting SYN, attempt %d", c.id, c.retries)
	c.retransmitSyn()
	c.armRTO()
}

// retransmitHead resends the first unacknowledged segment, for fast
// retransmit and NewReno partial ACKs.
func (c *Conn) retransmitHead() {
	c.timing.active = false
	c.stats.retransmits++
	offset := int(c.sndUna - c.sndBufSeq)
	n := min(c.sendBuf.Len()-offset, int(c.sendMSS))
	if n <= 0 {
		c.resendFin()
		return
	}
	payload := make([]byte, n)
	c.sendBuf.Peek(offset, payload)
	seg := c.newSegment(flagACK, c.sndUna)
	seg.payload = payload
	c.emit(&seg)
}

func (c *Conn) resendFin() {
	if !c.finSent || c.sndUna != c.finSeq {
		return
	}
	seg := c.newSegment(flagFIN|flagACK, c.finSeq)
	c.emit(&seg)
}

// maybeArmPersist starts probing when data is waiting behind a zero window
// and nothing is in flight to elicit a window update (RFC 9293 §3.8.6.1).
func (c *Conn) maybeArmPersist() {
	if c.sndWnd != 0 || c.sndNxt != c.sndUna || c.unsentBytes() <= 0 || c.persistTimer.active {
		return
	}
	c.persistTimer.arm(c, c.persistTimeout(), c.onPersist)
}

// onPersist sends a zero-window probe carrying an already acknowledged
// sequence number. The receiver must answer it with an ACK that advertises
// its current window. Probing continues with exponential backoff for as long
// as the window stays closed.
func (c *Conn) onPersist() {
	if c.sndWnd != 0 {
		c.trySend()
		return
	}
	seg := c.newSegment(flagACK, c.sndUna-1)
	c.emit(&seg)
	c.stats.probes++
	c.persistBackoff++
	c.logger.Debugf("netstack: %s zero window probe %d", c.id, c.stats.probes)
	c.persistTimer.arm(c, c.persistTimeout(), c.onPersist)
}

func (c *Conn) persistTimeout() time.Duration {
	d := c.rtt.rto
	for i := 0; i < c.persistBackoff && d < maxRTO; i++ {
		d *= 2
	}
	return min(d, maxRTO)
}
