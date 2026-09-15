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

package icmp

import (
	"encoding/binary"
	"sync"
	"time"
)

// initNewReno initializes the congestion control variables.
func (c *Conn) initNewReno() {
	// Initialize congestion control (all values in MSS units)
	c.cwnd.Store(10 * c.emss) // Start with 10 EMSS
	c.ssthresh = maxUint32Seq
	c.flightSize = NewFlightCounter(&c.cwnd, uint32(c.writeBuf.size)) // No data in flight initially
	c.transmitWg = sync.NewCond(&sync.Mutex{})
	c.rto = time.NewTimer(minRTO)
	c.rto.Stop()
	// Initialize sequence numbers
	c.seq.Store(0)         // Our sequence number
	c.ack.Store(0)         // Our acknowledgment number
	c.peerSeq = 0          // Peer's sequence number
	c.peerAck = 0xFFFFFFFF // Peer's acknowledgment number
	// Initial RTT estimate
	c.rtt.Store(int64(500 * time.Millisecond))
	// Initialize retransmit queue and out of order queue
	c.rq = NewRetransmitQueue(c.listener.clearMemory)
	c.ooq = NewRetransmitQueue(c.listener.clearMemory)
}

func min(a, b uint32) uint32 {
	if a < b {
		return a
	}
	return b
}

func max(a, b uint32) uint32 {
	if a > b {
		return a
	}
	return b
}

func (c *Conn) updateCongestionWindow(peerAck uint32) {
	if c.retransmit.Load() {
		return
	}
	ackedBytes := uint32SeqDiff(peerAck, c.peerAck)
	if c.cwnd.Load() >= c.ssthresh {
		// Congestion avoidance
		c.ackBytesCount += ackedBytes
		if c.ackBytesCount >= c.cwnd.Load() {
			c.ackBytesCount = 0
			c.cwnd.Add(c.emss)
		}
		return
	}
	// Slow start
	c.ackBytesCount = 0
	if ackedBytes > c.emss {
		ackedBytes = c.emss
	}
	c.cwnd.Add(ackedBytes)
}

func (c *Conn) blockTransmit() {
	c.transmitWg.L.Lock()
	c.transmitBlocked = true
	c.transmitWg.L.Unlock()
}
func (c *Conn) unblockTransmit() {
	if c.retransmit.Load() || c.recovery.Load() {
		return
	}
	c.transmitWg.L.Lock()
	if !c.transmitBlocked {
		c.transmitWg.L.Unlock()
		return
	}
	c.transmitBlocked = false
	c.transmitWg.Signal()
	c.transmitWg.L.Unlock()
}

func (c *Conn) waitTransmit() {
	c.transmitWg.L.Lock()
	for c.transmitBlocked {
		c.transmitWg.Wait()
	}
	c.transmitWg.L.Unlock()
}

func (c *Conn) handleDuplicateAck(ourSeq uint32, packet *Packet) (isDuplicateAck bool) {
	isDuplicateAck = len(packet.Data) == 0 && (packet.PacketAck == c.peerAck) && (isUint32SeqHigher(ourSeq, packet.PacketAck))
	if !isDuplicateAck {
		return
	}
	c.listener.logger.Tracef("Duplicate ACK, %s, OUR_SEQ: %d, OUR_ACK: %d, FLIGHT: %d", packet.PigPacket(), ourSeq, c.ack.Load(), uint16SeqDiff(ourSeq, packet.PacketAck))
	if c.retransmit.Load() {
		c.cwnd.Add(c.emss)
		return
	}
	// Triple duplicate ACK detection
	c.dupCnt++
	if c.dupCnt < 3 {
		return
	}

	if isUint32SeqHigher(c.recover.Load(), packet.PacketAck) {
		// rfc6582 section 4.1
		if c.cwnd.Load() <= c.emss {
			// the congestion window is too small
			return
		}
		if uint32SeqDiff(c.peerAck, c.prevPeerAck) > (4 * c.emss) {
			// this is likely the result of unnecessary retransmissions
			return
		}
	}
	c.listener.logger.Debugf("Triple duplicate ACK, %s", packet.PigPacket())

	c.recover.Store(ourSeq)

	c.blockTransmit()

	// ssthresh=max(FlightSize/2,2×MSS)
	c.ssthresh = max(c.flightSize.Load()/2, 2*c.emss)
	// Retransmit missing segment
	c.retransmitMissingSegment(packet.PacketAck)
	// cwnd=ssthresh+3×MSS
	c.cwnd.Store(c.ssthresh + 3*c.emss)
	c.listener.logger.Debugf("Fast retransmit triggered, new cwnd: %d", c.cwnd.Load())
	// Enter fast recovery
	c.retransmit.Store(true)
	return
}

func (c *Conn) doFastRetransmit(peerAck uint32) bool {
	if !c.retransmit.Load() {
		return false
	}
	if isUint32SeqHigher(c.recover.Load(), peerAck) {
		c.retransmitMissingSegment(peerAck)
		ackedBytes := uint32SeqDiff(peerAck, c.peerAck)
		if ackedBytes < c.emss {
			ackedBytes = c.emss
		}
		cwnd := c.ssthresh
		if ackedBytes < cwnd {
			c.cwnd.Store(cwnd + c.emss)
		}
		/*cwnd := c.cwnd.Load() - ackedBytes
		if ackedBytes >= c.emss {
			cwnd += c.emss
		}
		if cwnd > 0 {
			c.cwnd.Store(cwnd)
		}*/
		return true
	}
	// c.ackBytesCount = 0
	cwnd := c.ssthresh
	// cwnd := min(c.ssthresh, max(c.flightSize.Load(), c.emss))
	// reset RTO
	c.cwnd.Store(cwnd)
	c.rto.Reset(minRTO)
	// Exit recovery
	c.retransmit.Store(false) // we can now resume transmitting
	c.unblockTransmit()
	c.listener.logger.Debugf("Exiting fast retransmit, cwnd: %d", c.cwnd.Load())
	return false
}

func (c *Conn) recoverFromLoss(startSeq uint32) bool {
	numRecovered := 0
	c.listener.logger.Tracef("Recovering from loss, startSeq: %d", startSeq)
	c.ooq.RangeFrom(startSeq, func(packet *Packet, nextSeq uint32) bool {
		c.listener.logger.Tracef("Found packet in out of order queue: %s", packet.PigPacket())
		if packet.PacketAck > c.peerAck {
			c.peerAck = packet.PacketAck
		}
		if _, err := c.readBuf.Write(packet.Data); err != nil {
			c.listener.logger.Errorf("Error writing to read buffer: %v", err)
			return false
		}
		numRecovered++
		nextPeerSeq := packet.PacketSeq + uint32(len(packet.Data))
		c.peerSeq = nextPeerSeq
		return nextSeq == nextPeerSeq
	})
	c.listener.logger.Tracef("Recovered %d packets", numRecovered)
	// delete recovered packets from out of order queue
	c.ooq.DeleteUntil(c.peerSeq)
	// send an ack to let the peer know we recovered
	c.ack.Store(c.peerSeq)
	c.serializeAck(c.peerSeq)
	return numRecovered > 0
}

func (c *Conn) retransmitMissingSegment(peerAck uint32) {
	packet := c.rq.GetPacket(peerAck)
	if packet == nil {
		c.listener.logger.Debugf("No data to retransmit, peerAck: %d", peerAck)
		return
	}
	//packetSeq := binary.BigEndian.Uint32(packet[0:4])
	if packet.PacketSeq != peerAck {
		c.listener.logger.Errorf("mismatch in packet seq: %d, peerAck: %d", packet.PacketSeq, peerAck)
	}

	packet.PacketAck = c.ack.Load()
	binary.BigEndian.PutUint32(packet.IcmpPayload[4:8], packet.PacketAck)

	c.listener.logger.Tracef("Retransmitting packet: %s", packet.PigPacket())
	if err := c.serializeData(packet.IcmpPayload); err != nil {
		c.listener.logger.Errorf("Error retransmitting data: %v", err)
	}
}
