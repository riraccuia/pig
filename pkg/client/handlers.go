package client

import (
	"context"
	"io"

	"github.com/riraccuia/pig/pkg/packet"
)

// handleInbound starts the appropriate packet handling based on connection type
func (c *Client) handleInbound(ctx context.Context) {
	if c.conn.IsStreamed() {
		go c.openStreams(ctx)
		return
	}
	go c.processInbound(c.conn)
}

// handleOutbound manages outbound packet routing based on connection type
func (c *Client) handleOutbound(ctx context.Context) {
	if c.conn.IsStreamed() {
		go c.processOutboundStream(ctx)
		return
	}
	go c.processOutboundConn(ctx)
}

// processInbound processes incoming IPv4 packets from the connection or stream
// and forwards them to the local network adapter.
func (c *Client) processInbound(connOrStream io.ReadWriteCloser) {
	const readBufferSize = 64 * 1024 // 64KB buffer
	buffer := make([]byte, readBufferSize)
	unprocessed := buffer[:0]

	for {
		n, err := connOrStream.Read(buffer[len(unprocessed):])
		if err != nil {
			c.logger.Debugf("failed to read from connection or stream: %v", err)
			if c.conn.IsStreamed() {
				c.logger.Infof("stream closed, reconnecting")
				// streams are reconnected automatically
				return
			}
			select {
			case c.connError <- err:
			default:
			}
			return
		}
		unprocessed = buffer[:len(unprocessed)+n]

		// Process complete packets
		processed := 0
		for processed+20 <= len(unprocessed) {
			pkt := packet.IPv4Packet(unprocessed[processed:])
			totalLen := pkt.TotalLength()

			if totalLen < 20 || totalLen > c.config.MTU {
				c.logger.Debugf("received packet inbound with invalid length: %d", totalLen)
				processed++
				continue
			}

			if processed+totalLen > len(unprocessed) {
				break // Partial packet, wait for more data
			}

			// Get new packet from pool and copy data
			newPkt := c.bufferPool.Get().(packet.IPv4Packet)
			copy(newPkt[:totalLen], unprocessed[processed:processed+totalLen])
			switch newPkt.GetMark() {
			case packet.DSCP_MARK_ADAPTER_SNAT:
				newPkt.SetSourceIP(c.adapter.IP())
			case packet.DSCP_MARK_ADAPTER_DNAT:
				newPkt.SetDestinationIP(c.adapter.IP())
			case packet.DSCP_MARK_MASQ_SNAT:
				newPkt.SetSourceIP(c.masqAddr)
			}
			newPkt.ClearMark()
			newPkt.UpdateChecksum()
			select {
			case c.inbound <- newPkt:
			default:
				c.logger.Errorf("adapter inbound channel full, dropping packet")
				c.bufferPool.Put(newPkt)
			}

			processed += totalLen
		}

		// Preserve any remaining partial packet
		remaining := len(unprocessed) - processed
		if remaining == 0 {
			unprocessed = buffer[:0]
			continue
		}

		copy(buffer, unprocessed[processed:])
		unprocessed = buffer[:remaining]
	}
}

// processOutboundStream processes outbound packets for streamed connections,
// selecting appropriate streams based on destination IP
func (c *Client) processOutboundStream(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case pkt, ok := <-c.outbound.C:
			if !ok {
				return
			}
			if c.outbound.IsDrop() {
				c.dropLogger.Incr(1, uint64(pkt.TotalLength()))
				c.bufferPool.Put(pkt)
				continue
			}
			stream := c.streams.SelectByIPAndPort(pkt.DestinationIP(), pkt.DestinationPort())
			if stream == nil {
				c.bufferPool.Put(pkt)
				continue
			}

			totalLen := pkt.TotalLength()
			if totalLen <= 0 || totalLen > len(pkt) {
				c.bufferPool.Put(pkt)
				continue
			}

			switch {
			case c.adapter.IP().Equal(pkt.SourceIP()):
				pkt.Mark(packet.DSCP_MARK_MASQ_SNAT)
			case c.masqAddr.Equal(pkt.DestinationIP()):
				pkt.Mark(packet.DSCP_MARK_ADAPTER_DNAT)
			}

			_, err := stream.Write(pkt[:totalLen])
			stream.Flush()
			c.bufferPool.Put(pkt)
			if err == nil {
				continue
			}
			c.logger.Errorf("failed to write to stream: %v", err)
			stream.Close()
			return
		}
	}
}

// processOutboundConn processes outbound packets for non-streamed connections
func (c *Client) processOutboundConn(ctx context.Context) {
	// Create a buffer to hold multiple packets
	const maxBatchSize = 64 * 1024 // 64KB batch size
	buffer := make([]byte, 0, maxBatchSize)
	batch := buffer[:0]

	// Helper function to write and reset batch
	writeBatch := func() error {
		for len(batch) > 0 {
			n, err := c.conn.Write(batch)
			batch = batch[n:]
			if err != nil && err != io.ErrShortWrite {
				return err
			}
		}
		batch = buffer[:0]
		return nil
	}

	processPacket := func(pkt packet.IPv4Packet) error {
		if c.outbound.IsDrop() {
			c.dropLogger.Incr(1, uint64(pkt.TotalLength()))
			c.bufferPool.Put(pkt)
			return nil
		}
		totalLen := pkt.TotalLength()
		if totalLen <= 0 || totalLen > len(pkt) {
			c.bufferPool.Put(pkt)
			return nil
		}

		switch {
		case c.adapter.IP().Equal(pkt.SourceIP()):
			pkt.Mark(packet.DSCP_MARK_MASQ_SNAT)
		case c.masqAddr.Equal(pkt.DestinationIP()):
			pkt.Mark(packet.DSCP_MARK_ADAPTER_DNAT)
		}

		// If adding this packet would exceed batch size, flush current batch first
		if len(batch)+totalLen > maxBatchSize {
			if err := writeBatch(); err != nil {
				c.bufferPool.Put(pkt)
				c.logger.Debugf("failed to write batch to connection: %v", err)
				return err
			}
		}

		// Append packet to batch
		batch = append(batch, pkt[:totalLen]...)
		c.bufferPool.Put(pkt)

		// If batch is full, write immediately
		if len(batch) >= maxBatchSize {
			if err := writeBatch(); err != nil {
				c.logger.Debugf("failed to write batch to connection: %v", err)
				return err
			}
		}
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case pkt, ok := <-c.outbound.C:
			if !ok {
				return
			}
			// process all queued packets fast
			for {
				if err := processPacket(pkt); err != nil {
					c.logger.Debugf("failed to process packet: %v", err)
					return
				}
				if len(c.outbound.C) == 0 {
					break
				}
				pkt = <-c.outbound.C
			}
			// write any remaining data
			writeBatch()
		}
	}
}
