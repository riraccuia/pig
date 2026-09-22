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

func (s *Server) acceptClients(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
			_co, err := s.listener.Accept()
			if err != nil {
				return
			}
			var (
				conn transport.Conn
				ok   bool
			)
			if conn, ok = _co.(transport.Conn); !ok {
				s.logger.Errorf("accepted connection is not a transport.Conn: %v", _co)
				_co.Close()
				continue
			}
			if err := s.performAuthentication(ctx, conn); err != nil {
				conn.Close()
				continue
			}
			go s.handleNewClient(ctx, conn)
		}
	}
}

func (s *Server) handleInbound(client *ClientTunnel, connOrStream io.ReadWriteCloser) {
	// assign a queue to the client
	inbound := s.getInboundPktQueue()

	const readBufferSize = 64 * 1024 // 64KB buffer
	buffer := make([]byte, readBufferSize)
	unprocessed := buffer[:0]

	for {
		// Read more data
		n, err := connOrStream.Read(buffer[len(unprocessed):])
		if err != nil {
			s.logger.Errorf("error reading from client (%s) conn or stream: %v", client.conn.RemoteAddr(), err)
			if client.conn.IsStreamed() {
				// streams are reconnected by the client
				return
			}
			select {
			case client.connError <- err:
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

			if processed+totalLen > len(unprocessed) {
				break // Partial packet, wait for more data
			}

			if totalLen > s.adapterCfg.MTU {
				s.logger.Debugf("IPv=%d,len=%d,proto=%d | %d%s->%s:%d | discarded, too long",
					prePkt.Version(), totalLen, prePkt.Protocol(),
					prePkt.SourcePort(), prePkt.SourceIP(),
					prePkt.DestinationIP(), prePkt.DestinationPort(),
				)
				// discard packet
				processed += totalLen
				continue
			}

			// Get new packet from pool and copy data
			buf := s.bufferPool.Get().([]byte)
			copy(buf[:totalLen], unprocessed[processed:processed+totalLen])

			var pkt network.IPPacket
			switch prePkt.Version() {
			case 4:
				v4Pkt := network.IPv4Packet(buf[:])
				v4Pkt.SetSourceIP(client.sourceIP)
				pkt = v4Pkt
			case 6:
				v6Pkt := network.IPv6Packet(buf[:])
				if client.sourceIP6 != nil {
					v6Pkt.SetSourceIP(client.sourceIP6)
				}
				pkt = v6Pkt
			}

			pkt.UpdateChecksum()

			select {
			case inbound <- pkt:
			default:
				s.bufferPool.Put(buf)
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
