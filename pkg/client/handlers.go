package client

import (
	"context"
	"io"
	"time"

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
		go c.processOutboundStream()
		return
	}
	go c.processOutboundConn()
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
			c.logger.Errorf("failed to read from connection or stream: %v", err)
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
			newPkt.SetDestinationIP(c.adapter.IP())
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
func (c *Client) processOutboundStream() {
	for {
		pkt := <-c.outbound.C
		if c.outbound.IsDrop() {
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

// processOutboundConn processes outbound packets for non-streamed connections
func (c *Client) processOutboundConn() {
	// Create a buffer to hold multiple packets
	const maxBatchSize = 64 * 1024 // 64KB batch size
	buffer := make([]byte, 0, maxBatchSize)
	batch := buffer[:0]
	// Create a timer for flushing partial batches
	flushTicker := time.NewTicker(5 * time.Millisecond)
	defer flushTicker.Stop()

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
	for {
		select {
		case <-flushTicker.C:
			if err := writeBatch(); err != nil {
				c.logger.Errorf("failed to write batch to connection: %v", err)
				return
			}
		case pkt, ok := <-c.outbound.C:
			if !ok {
				return
			}
			if c.outbound.IsDrop() {
				c.logger.Infof("dropping packet, queue length: %d", len(c.outbound.C))
				c.bufferPool.Put(pkt)
				continue
			}
			totalLen := pkt.TotalLength()
			if totalLen <= 0 || totalLen > len(pkt) {
				c.bufferPool.Put(pkt)
				continue
			}

			// If adding this packet would exceed batch size, flush current batch first
			if len(batch)+totalLen > maxBatchSize {
				if err := writeBatch(); err != nil {
					c.bufferPool.Put(pkt)
					c.logger.Errorf("failed to write batch to connection: %v", err)
					return
				}
			}

			// Append packet to batch
			batch = append(batch, pkt[:totalLen]...)
			c.bufferPool.Put(pkt)

			// If batch is full, write immediately
			if len(batch) >= maxBatchSize {
				if err := writeBatch(); err != nil {
					c.logger.Errorf("failed to write batch to connection: %v", err)
					return
				}
			}
		}
	}
}
