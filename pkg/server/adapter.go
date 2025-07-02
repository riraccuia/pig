package server

import (
	"context"

	"github.com/riraccuia/pig/pkg/packet"
)

func (s *Server) processOutbound(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-s.outbound:
			_client, ok := s.clients.Load(pkt.DestinationIP().String())
			if !ok {
				freeBuf := true
				s.clients.Range(func(key, value any) bool {
					client := value.(*ClientTunnel)
					pkt.Mark(packet.DSCP_MARK_MASQ_SNAT)
					select {
					case client.outbound.C <- pkt:
						freeBuf = false
					default:
					}
					return true
				})
				if freeBuf {
					s.bufferPool.Put(pkt)
				}
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
