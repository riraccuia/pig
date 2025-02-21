package server

import (
	"context"

	"github.com/riraccuia/pig/pkg/packet"
)

func (s *Server) processInboundQueue(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-s.inbound:
			totalLen := pkt.TotalLength()
			if totalLen > 0 && totalLen <= len(pkt[:totalLen]) {
				_, err := s.adapter.Write(pkt[:totalLen])
				s.bufferPool.Put(pkt)
				if err != nil {
					continue
				}
			} else {
				s.bufferPool.Put(pkt)
			}
		}
	}
}

func (s *Server) processOutboundQueue(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-s.outbound:
			_client, ok := s.clients.Load(pkt.DestinationIP().String())
			if !ok {
				s.bufferPool.Put(pkt)
				continue
			}
			client := _client.(*ClientTunnel)

			select {
			case client.outbound.C <- pkt:
			default:
				s.bufferPool.Put(pkt)
			}
		}
	}
}

func (s *Server) readFromAdapter() {
	for {
		buffer := s.bufferPool.Get().(packet.IPv4Packet)
		n, err := s.adapter.Read(buffer)
		if err != nil {
			s.bufferPool.Put(buffer)
			return
		}

		pkt := buffer[:n]
		if pkt.Version() != 4 {
			s.bufferPool.Put(buffer)
			continue
		}

		select {
		case s.outbound <- buffer:
		default:
			s.bufferPool.Put(buffer)
		}
	}
}
