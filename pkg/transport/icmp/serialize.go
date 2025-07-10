package icmp

import (
	"encoding/binary"
	"fmt"
	"time"
)

func (c *Conn) serializeDuplicateAck(seq, ack uint32) error {
	data := make([]byte, eHeaderSize)
	binary.BigEndian.PutUint32(data[0:4], seq)
	binary.BigEndian.PutUint32(data[4:8], ack)

	if err := c.sendEchoMessage(data); err != nil {
		return fmt.Errorf("error sending duplicate ack: %w", err)
	}
	return nil
}

func (c *Conn) serializeAck(ack uint32) error {
	lastSentAck := c.sentAck.Load()
	if lastSentAck == ack || isUint32SeqHigher(lastSentAck, ack) {
		return nil
	}

	if !c.sentAck.CompareAndSwap(lastSentAck, ack) {
		return nil
	}

	data := make([]byte, 8)
	binary.BigEndian.PutUint32(data[0:4], c.seq.Load())
	binary.BigEndian.PutUint32(data[4:8], ack)

	if err := c.sendEchoMessage(data); err != nil {
		return fmt.Errorf("error sending duplicate ack: %w", err)
	}

	return nil
}

func (c *Conn) serializeData(icmpPayload []byte) error {
	if err := c.sendEchoMessage(icmpPayload); err != nil {
		return fmt.Errorf("error sending retransmit data: %w", err)
	}
	return nil
}

// serializeOutboundData serializes the application data and sends it.
// It also updates the sequence number and adds the data to the retransmit queue.
// This is the only function that should be used to send application data.
func (c *Conn) serializeOutboundData() error {
	rawBuf := c.listener.getBuffer()
	n, err := c.writeBuf.Read(rawBuf[eHeaderSize : eHeaderSize+c.emss])
	if err != nil {
		c.listener.clearMemory(rawBuf)
		return fmt.Errorf("error reading data for sending: %w", err)
	}

	seq, ack := c.seq.Load(), c.ack.Load()
	// update the sent ack number
	c.sentAck.CompareAndSwap(c.sentAck.Load(), ack)

	// Prepare sequence and acknowledgment
	binary.BigEndian.PutUint32(rawBuf[0:4], seq)
	binary.BigEndian.PutUint32(rawBuf[4:8], ack)

	// Update sequence number and flight size
	c.seq.Add(uint32(n))
	c.flightSize.Add(uint32(n)) // Send data

	packet := &Packet{
		PacketSeq:   seq,
		PacketAck:   ack,
		IcmpPayload: rawBuf[:eHeaderSize+n],
		Data:        rawBuf[eHeaderSize : eHeaderSize+n],
		buffer:      rawBuf,
	}

	// Store in retransmit queue
	c.rq.Put(packet)

	if err := c.sendEchoMessage(packet.IcmpPayload); err != nil {
		// Store in retransmit queue
		return fmt.Errorf("error sending data: %w", err)
	}

	c.rtoSeq.Store(&measurement{
		sendTime: time.Now(),
		seq:      c.seq.Load(),
	})
	// transport.Logger.Infof("Sent data packet, len: %d, nextseq: %d, ack: %d", n, c.seq.Load(), c.ack.Load())

	return nil

	/*rawBuf := c.listener.bufPool.Get().(*rawSockBuffer)
	rawBuf.po = 0
	rawBuf.len = icmpHeaderSize
	buf := rawBuf.b[icmpHeaderSize:]
	// Read data from buffer, limited by EMSS
	n, err := c.writeBuf.Read(buf[eHeaderSize : eHeaderSize+c.emss])
	if err != nil {
		c.listener.clearMemory(rawBuf)
		return fmt.Errorf("error reading data for sending: %w", err)
	}

	rawBuf.len += eHeaderSize + n

	seq, ack := c.seq.Load(), c.ack.Load()

	// update the sent ack number
	c.sentAck.CompareAndSwap(c.sentAck.Load(), ack)

	// Prepare sequence and acknowledgment
	binary.BigEndian.PutUint32(buf[0:4], seq)
	binary.BigEndian.PutUint32(buf[4:8], ack)

	// Update sequence number and flight size
	c.seq.Add(uint32(n))
	c.flightSize.Add(uint32(n)) // Send data

	//c.listener.logger.Debugf("Sending data packet, len: %d, seq: %d, nextseq: %d, ack: %d, icmpseq: %d", n, seq, c.seq.Load(), c.ack.Load(), c.nextIcmpSeq.Load())

	if err := c.sendEchoMessage(buf[:eHeaderSize+n]); err != nil {
		// Store in retransmit queue
		c.rq.Put(rawBuf)
		return fmt.Errorf("error sending data: %w", err)
	}

	// Store in retransmit queue
	c.rq.Put(rawBuf)

	c.rtoSeq.Store(&measurement{
		sendTime: time.Now(),
		seq:      c.seq.Load(),
	})
	// transport.Logger.Infof("Sent data packet, len: %d, nextseq: %d, ack: %d", n, c.seq.Load(), c.ack.Load())

	return nil*/
}
