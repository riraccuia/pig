package server

import "context"

func (s *Server) processOutbound(ctx context.Context) {
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
