package server

import (
	"context"
	"io"

	"github.com/riraccuia/pig/pkg/packet"
)

func (s *Server) acceptClients(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.done:
			return
		default:
			conn, err := s.listener.Accept(ctx)
			if err != nil {
				return
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
	// inbound := s.getInboundPktQueue()

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
			pkt := packet.IPv4Packet(unprocessed[processed:])
			totalLen := pkt.TotalLength()

			if totalLen < 20 || totalLen > s.config.MTU {
				processed++
				continue
			}

			if processed+totalLen > len(unprocessed) {
				break // Partial packet, wait for more data
			}

			// Get new packet from pool and copy data
			newPkt := s.bufferPool.Get().(packet.IPv4Packet)
			copy(newPkt[:totalLen], unprocessed[processed:processed+totalLen])

			switch newPkt.GetMark() {
			case packet.DSCP_MARK_MASQ_SNAT:
				newPkt.SetSourceIP(client.sourceIP)
			case packet.DSCP_MARK_MASQ_DNAT:
				newPkt.SetDestinationIP(client.sourceIP)
			case packet.DSCP_MARK_ADAPTER_DNAT:
				newPkt.SetDestinationIP(s.adapter.IP())
			}
			newPkt.ClearMark()
			newPkt.UpdateChecksum()

			inbound := s.getInboundPktQueue()

			select {
			case inbound <- newPkt:
			default:
				s.bufferPool.Put(newPkt)
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
