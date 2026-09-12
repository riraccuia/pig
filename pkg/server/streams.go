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

package server

import (
	"context"
	"io"

	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/transport"
)

// acceptStreams handles incoming stream connections from the QUIC transport.
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
				select {
				case client.connError <- err:
				default:
				}
				return
			}

			s.logger.Debugf("accepted stream from client %s", client.conn.RemoteAddr())

			stream.Flush()
			client.streams.Add(stream)

			go s.handleStream(client, stream)
		}
	}
}

func (s *Server) handleOutbound(ctx context.Context, client *ClientTunnel) {
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

	processPacket := func(pkt network.IPPacket) error {
		if client.outbound.IsDrop() {
			client.dropLogger.Incr(1, uint64(pkt.TotalLength()))
			s.bufferPool.Put(pkt.Bytes())
			return nil
		}
		totalLen := pkt.TotalLength()
		if totalLen <= 0 || totalLen > len(pkt.Bytes()) {
			s.logger.Debugf("outbound packet with invalid length: %d", totalLen)
			s.bufferPool.Put(pkt.Bytes())
			return nil
		}

		// If adding this packet would exceed batch size, flush current batch first
		if len(batch)+totalLen > maxBatchSize {
			if err := writeBatch(); err != nil {
				s.bufferPool.Put(pkt.Bytes())
				return err
			}
		}

		// Append packet to batch
		batch = append(batch, pkt.Bytes()[:totalLen]...)
		s.bufferPool.Put(pkt.Bytes())

		// If batch is full, write immediately
		if len(batch) >= maxBatchSize {
			if err := writeBatch(); err != nil {
				s.bufferPool.Put(pkt.Bytes())
				return err
			}
		}
		return nil
	}

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
			// process all queued packets fast
			for {
				if err := processPacket(pkt); err != nil {
					s.logger.Debugf("failed to process packet: %v", err)
					return
				}
				if len(client.outbound.C) == 0 {
					break
				}
				pkt = <-client.outbound.C
			}
			// write any remaining data
			if err := writeBatch(); err != nil {
				s.logger.Errorf("failed to send outbound data: %v", err)
				return
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
				s.bufferPool.Put(pkt.Bytes())
				continue
			}
			totalLen := pkt.TotalLength()
			if totalLen <= 0 || totalLen > len(pkt.Bytes()) {
				s.bufferPool.Put(pkt.Bytes())
				continue
			}

			stream := client.streams.SelectByIPAndPort(pkt.SourceIP(), pkt.SourcePort())
			if stream == nil {
				s.logger.Infof("no stream found for client %s", client.conn.RemoteAddr())
				s.bufferPool.Put(pkt.Bytes())
				continue
			}
			_, err := stream.Write(pkt.Bytes()[:totalLen])
			stream.Flush()
			s.bufferPool.Put(pkt.Bytes())
			if err != nil {
				return
			}
		}
	}
}

func (s *Server) handleStream(client *ClientTunnel, stream transport.Stream) {
	defer func() {
		client.streams.Remove(stream)
		stream.Close()
	}()
	s.handleInbound(client, stream)
}
