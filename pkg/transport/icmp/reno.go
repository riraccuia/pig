package icmp

import (
	"encoding/binary"
	"time"

	"github.com/riraccuia/pig/pkg/transport"
)

// initNewReno initializes the congestion control variables
func (c *connection) initNewReno() {
	// Initialize congestion control (all values in MSS units)
	c.cwnd.Store(3 * c.emss) // Start with 3 EMSS
	c.ssthresh = defaultBufferSize
	c.flightSize = NewFlightCounter(&c.cwnd) // No data in flight initially
	c.rto = time.NewTimer(minRTO)
	c.rto.Stop()
	// Initialize sequence numbers
	c.seq.Store(0)         // Our sequence number
	c.ack.Store(0)         // Our acknowledgment number
	c.peerSeq = 0          // Peer's sequence number
	c.peerAck = 0xFFFFFFFF // Peer's acknowledgment number

	// Initial RTT estimate
	c.rtt.Store(int64(500 * time.Millisecond))

	c.rq = NewRetransmitQueue(c.clearMemory)
	c.ooq = NewRetransmitQueue(c.clearMemory)
}

func (c *connection) clearMemory(m *rawSockBuffer) {
	m.po = 0
	m.len = 0
	c.listener.bufPool.Put(m)
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

func (c *connection) updateCongestionWindow(peerAck uint32) {
	if c.retransmit.Load() {
		return
	}
	ackedBytes := uint32SeqDiff(peerAck, c.peerAck)
	if c.cwnd.Load() < c.ssthresh {
		// Slow start
		incr := c.emss
		if ackedBytes > incr {
			incr = (ackedBytes / c.emss) * c.emss
		}
		c.cwnd.Add(min(ackedBytes, incr))
		return
	}
	// Congestion avoidance
	c.ackBytesCount += ackedBytes
	if c.ackBytesCount < c.cwnd.Load() {
		return
	}
	c.ackBytesCount = 0
	c.cwnd.Add(c.emss)
	// transport.Logger.Infof("Congestion avoidance, cwnd increased by %d to %d", delta, c.getCwnd())
}

func (c *connection) handleDuplicateAck(ourSeq, peerSeq, peerAck uint32, data []byte) (isDuplicateAck bool) {
	isDuplicateAck = len(data) == 0 /*&& (peerSeq == c.peerSeq)*/ && (peerAck == c.peerAck) && (isUint32SeqHigher(ourSeq, peerAck))
	if !isDuplicateAck {
		return
	}
	transport.Logger.Debugf("Duplicate ACK, seq: %d, ack: %d, our_seq: %d, our_ack: %d", peerSeq, peerAck, ourSeq, c.ack.Load())
	if c.retransmit.Load() {
		c.cwnd.Add(c.emss)
		return
	}
	// Triple duplicate ACK detection
	c.dupCnt++
	if c.dupCnt < 3 {
		return
	}
	transport.Logger.Debugf("Triple duplicate ACK, seq: %d, ack: %d", peerSeq, peerAck)
	// Enter fast recovery
	c.retransmit.Store(true)
	c.recover.Store(ourSeq)
	// Fast retransmit - halve cwnd and set ssthresh
	// ssthresh=max(FlightSize/2,2×MSS)
	c.ssthresh = max(c.flightSize.Load()/2, 2*c.emss)
	// cwnd=ssthresh+3×MSS
	c.cwnd.Store(c.ssthresh + 3*c.emss)
	transport.Logger.Debugf("Fast retransmit triggered, new cwnd: %d", c.cwnd.Load())
	// Retransmit missing segment
	c.retransmitMissingSegment(peerAck)
	return
}

func (c *connection) doFastRetransmit(peerAck uint32) {
	if !c.retransmit.Load() {
		return
	}
	if isUint32SeqHigher(c.recover.Load(), peerAck) {
		ackedBytes := uint32SeqDiff(peerAck, c.peerAck)
		cwnd := c.cwnd.Load() - ackedBytes
		if ackedBytes >= c.emss {
			cwnd += c.emss
		}
		if cwnd > 0 {
			c.cwnd.Store(cwnd)
		}
		c.retransmitMissingSegment(peerAck)
		return
	}
	// Exit recovery
	c.retransmit.Store(false)
	c.ackBytesCount = 0
	// cwnd=ssthresh
	cwnd := min(c.ssthresh, max(c.flightSize.Load(), c.emss))
	c.cwnd.Store(cwnd)
	transport.Logger.Debugf("Exiting fast retransmit")
}

func (c *connection) recoverFromLoss(startSeq uint32) {
	var (
		purge       bool
		prevPeerSeq = c.peerSeq
		peerAck     = c.peerAck
	)
	transport.Logger.Debugf("Recovering from loss, startSeq: %d", startSeq)
	c.ooq.RangeFrom(startSeq, func(seq uint32, nextSeq uint32, sData []byte) bool {
		transport.Logger.Debugf("Found packet in out of order queue, seq: %d", seq)
		purge = true
		prevPeerSeq = seq
		peerAck = binary.BigEndian.Uint32(sData[4:8])
		if peerAck > c.peerAck {
			c.peerAck = peerAck
		}
		// c.updateCongestionWindow()
		if _, err := c.readBuf.Write(sData[8:]); err != nil {
			transport.Logger.Errorf("Error writing to read buffer: %v", err)
			return false
		}
		nextPeerSeq := seq + uint32(len(sData[8:]))
		c.peerSeq = nextPeerSeq
		return nextSeq == nextPeerSeq
	})
	if !purge {
		c.recovery = false
		return
	}
	c.ooq.DeleteUntil(prevPeerSeq)
	c.ack.Store(c.peerSeq)
	c.serializeAck(c.peerSeq)
	c.recovery = false
}

func (c *connection) retransmitMissingSegment(peerAck uint32) {
	packet := c.rq.GetPacket(peerAck)
	if packet == nil {
		transport.Logger.Debugf("No data to retransmit, peerAck: %d", peerAck)
		return
	}
	packetSeq := binary.BigEndian.Uint32(packet[0:4])
	if packetSeq != peerAck {
		transport.Logger.Errorf("mismatch in packet seq: %d, peerAck: %d", packetSeq, peerAck)
	}
	// transport.Logger.Infof("First retransmit packet seq: %v", c.rq.packets[0].seq)
	transport.Logger.Debugf("Retransmitting seq: %d, ack: %d, len: %d", peerAck, c.ack.Load(), len(packet))
	if err := c.serializeRetransmitData(peerAck, c.ack.Load(), packet); err != nil {
		transport.Logger.Errorf("Error retransmitting data: %v", err)
	}
}
