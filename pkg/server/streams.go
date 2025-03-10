package server

import (
	"context"
	"io"
	"time"

	"github.com/riraccuia/pig/pkg/packet"
	"github.com/riraccuia/pig/pkg/transport"
)

// acceptStreams handles incoming stream connections from the QUIC transport
func (s *Server) acceptStreams(ctx context.Context, client *ClientTunnel) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
			stream, err := client.conn.AcceptStream(ctx)
			if err != nil {
				s.logger.Errorf("failed to accept client (%s) stream: %v", client.conn.RemoteAddr(), err)
				select {
				case client.connError <- err:
				default:
				}
				return
			}

			stream.Flush()
			client.streams.Add(stream)

			go s.handleStream(client, stream)
		}
	}
}

func (s *Server) handleOutbound(ctx context.Context, client *ClientTunnel) {
	defer func() {
		s.ipPool.Release(client.sourceIP)
		client.streams.CloseAll()
	}()
	if client.conn.IsStreamed() {
		s.handleOutboundStream(ctx, client)
		return
	}
	s.handleOutboundConn(ctx, client)
}

func (s *Server) handleOutboundConn(ctx context.Context, client *ClientTunnel) {
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
			n, err := client.conn.Write(batch)
			batch = batch[n:]
			if err != nil && err != io.ErrShortWrite {
				s.logger.Errorf("failed to write outbound data to connection: %v", err)
				return err
			}
		}
		batch = buffer[:0]
		return nil
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case <-flushTicker.C:
			if err := writeBatch(); err != nil {
				return
			}
		case pkt, ok := <-client.outbound.C:
			if !ok {
				return
			}
			if client.outbound.IsDrop() {
				client.dropLogger.Incr(1, uint64(pkt.TotalLength()))
				s.bufferPool.Put(pkt)
				continue
			}
			ipPkt := packet.IPv4Packet(pkt)
			totalLen := ipPkt.TotalLength()
			if totalLen <= 0 || totalLen > len(pkt) {
				s.logger.Debugf("outbound packet with invalid length: %d", totalLen)
				s.bufferPool.Put(pkt)
				continue
			}

			// If adding this packet would exceed batch size, flush current batch first
			if len(batch)+totalLen > maxBatchSize {
				if err := writeBatch(); err != nil {
					s.bufferPool.Put(pkt)
					return
				}
			}

			// Append packet to batch
			batch = append(batch, pkt[:totalLen]...)
			s.bufferPool.Put(pkt)

			// If batch is full, write immediately
			if len(batch) >= maxBatchSize {
				if err := writeBatch(); err != nil {
					return
				}
			}
		}
	}
}

func (s *Server) handleOutboundStream(ctx context.Context, client *ClientTunnel) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		case pkt, ok := <-client.outbound.C:
			if !ok {
				return
			}
			if client.outbound.IsDrop() {
				client.dropLogger.Incr(1, uint64(pkt.TotalLength()))
				s.bufferPool.Put(pkt)
				continue
			}
			ipPkt := packet.IPv4Packet(pkt)
			totalLen := ipPkt.TotalLength()
			if totalLen <= 0 || totalLen > len(pkt) {
				s.bufferPool.Put(pkt)
				continue
			}
			stream := client.streams.SelectByIPAndPort(pkt.SourceIP(), pkt.SourcePort())
			if stream == nil {
				s.logger.Infof("no stream found for client %s", client.conn.RemoteAddr())
				s.bufferPool.Put(pkt)
				continue
			}
			_, err := stream.Write(pkt[:totalLen])
			stream.Flush()
			s.bufferPool.Put(pkt)
			if err != nil {
				return
			}
		}
	}
}

func (s *Server) handleStream(client *ClientTunnel, stream transport.Stream) {
	defer func() {
		client.streams.Remove(stream)
		//go s.reconnectStream(client)
		stream.Close()
	}()
	s.handleInbound(client, stream)
}
