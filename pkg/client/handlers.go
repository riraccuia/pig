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

package client

import (
	"context"
	"io"

	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/transport"
)

// handleInbound starts the appropriate packet handling based on connection type.
func (c *Client) handleInbound(ctx context.Context) {
	if c.conn.IsStreamed() {
		go c.openStreams(ctx)
		return
	}
	go c.processInbound(c.conn)
}

// handleOutbound manages outbound packet routing based on connection type.
func (c *Client) handleOutbound(ctx context.Context) {
	if c.conn == nil {
		c.logger.Debugf("no connection, skipping outbound packet handling")
		return
	}
	if c.conn.IsStreamed() {
		go c.processOutboundStream(ctx)
		return
	}
	go c.processOutboundConn(ctx, c.conn)
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
			if conn, ok := connOrStream.(transport.Conn); ok && conn.IsStreamed() {
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
			var prePkt network.IPPacket

			switch network.IPv4Packet(unprocessed[processed:]).Version() {
			case 4:
				prePkt = network.IPv4Packet(unprocessed[processed:])
			case 6:
				prePkt = network.IPv6Packet(unprocessed[processed:])
			}

			totalLen := prePkt.TotalLength()

			if totalLen < 20 || totalLen > c.mtu {
				c.logger.Debugf("received packet inbound with invalid length: %d", totalLen)
				processed++
				continue
			}

			if processed+totalLen > len(unprocessed) {
				break // Partial packet, wait for more data
			}

			// Get new packet from pool and copy data
			buf := c.bufferPool.GetBuffer(c.mtu)
			copy(buf[:totalLen], unprocessed[processed:processed+totalLen])

			var pkt network.IPPacket

			switch prePkt.Version() {
			case 4:
				v4Pkt := network.IPv4Packet(buf[:])
				tuple, _ := NewTuple(v4Pkt)
				tuple.DestIP = c.adapter.IP()
				entry, ok := c.conntrack.Load(tuple)
				if !ok {
					pkt = v4Pkt
					break
				}
				entry.UpdateExpireAt(tuple.ProtocolData)
				if entry.InMappedDst != nil {
					v4Pkt.SetDestinationIP(entry.InMappedDst)
				}
				pkt = v4Pkt
			case 6:
				pkt = network.IPv6Packet(buf[:])
				pkt.SetDestinationIP(c.adapter.IP6())
			}

			pkt.UpdateChecksum()
			select {
			case c.inbound <- pkt:
			default:
				c.logger.Errorf("adapter inbound channel full, dropping packet")
				c.bufferPool.PutBuffer(pkt.Bytes())
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
// selecting appropriate streams based on destination IP.
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
			stream := c.streams.SelectByIPAndPort(pkt.DestinationIP(), pkt.DestinationPort())
			if stream == nil {
				c.bufferPool.PutBuffer(pkt.Bytes())
				continue
			}

			totalLen := pkt.TotalLength()
			if totalLen <= 0 || totalLen > len(pkt.Bytes()) {
				c.bufferPool.PutBuffer(pkt.Bytes())
				continue
			}

			switch realPkt := pkt.(type) {
			case network.IPv4Packet:
				tuple, _ := NewTuple(realPkt)
				entry, ok := c.conntrack.Load(tuple)
				if !ok {
					entry = &ConnTrackEntry{
						InMappedDst: tuple.SrcIP,
					}
					entry.UpdateExpireAt(tuple.ProtocolData)

					invertedTuple := tuple.Inverted()
					invertedTuple.DestIP = c.adapter.IP()

					c.conntrack.Store(tuple, entry)
					c.conntrack.Store(invertedTuple, entry)
					break
				}
				entry.UpdateExpireAt(tuple.ProtocolData)
			case network.IPv6Packet:
			}

			_, err := stream.Write(pkt.Bytes()[:totalLen])
			stream.Flush()
			c.bufferPool.PutBuffer(pkt.Bytes())
			if err == nil {
				continue
			}
			c.logger.Errorf("failed to write to stream: %v", err)
			stream.Close()
			return
		}
	}
}

// processOutboundConn processes outbound packets for non-streamed connections.
func (c *Client) processOutboundConn(ctx context.Context, conn transport.Conn) {
	// Create a buffer to hold multiple packets
	const maxBatchSize = 64 * 1024 // 64KB batch size
	buffer := make([]byte, 0, maxBatchSize)
	batch := buffer[:0]

	// Helper function to write and reset batch
	writeBatch := func() error {
		for len(batch) > 0 {
			n, err := conn.Write(batch)
			batch = batch[n:]
			if err != nil && err != io.ErrShortWrite {
				return err
			}
		}
		batch = buffer[:0]
		return nil
	}

	processPacket := func(pkt network.IPPacket) error {
		totalLen := pkt.TotalLength()
		if totalLen <= 0 || totalLen > len(pkt.Bytes()) {
			c.bufferPool.PutBuffer(pkt.Bytes())
			return nil
		}

		switch realPkt := pkt.(type) {
		case network.IPv4Packet:
			tuple, _ := NewTuple(realPkt)
			entry, ok := c.conntrack.Load(tuple)
			if !ok {
				entry = &ConnTrackEntry{
					InMappedDst: tuple.SrcIP,
				}
				entry.UpdateExpireAt(tuple.ProtocolData)

				invertedTuple := tuple.Inverted()
				invertedTuple.DestIP = c.adapter.IP()

				c.conntrack.Store(tuple, entry)
				c.conntrack.Store(invertedTuple, entry)
				break
			}
			entry.UpdateExpireAt(tuple.ProtocolData)
		case network.IPv6Packet:
		}

		// If adding this packet would exceed batch size, flush current batch first
		if len(batch)+totalLen > maxBatchSize {
			if err := writeBatch(); err != nil {
				c.bufferPool.PutBuffer(pkt.Bytes())
				c.logger.Debugf("failed to write batch to connection: %v", err)
				return err
			}
		}

		// Append packet to batch
		batch = append(batch, pkt.Bytes()[:totalLen]...)
		c.bufferPool.PutBuffer(pkt.Bytes())

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
		var (
			pkt network.IPPacket
			ok  bool
		)
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case pkt, ok = <-c.outbound.C:
		default:
			// write the data quickly when the channel has no more packets
			writeBatch()
			// then block again until a new packet is available
			select {
			case <-ctx.Done():
			case <-c.done:
			case pkt, ok = <-c.outbound.C:
			}
		}
		if !ok {
			writeBatch()
			return
		}
		if pkt == nil {
			writeBatch()
			continue
		}
		err := processPacket(pkt)
		if err != nil {
			c.logger.Debugf("failed to process packet: %v", err)
			return
		}
	}
}
