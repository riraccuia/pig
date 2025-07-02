//go:build linux
// +build linux

package server

import (
	"context"
	"io"

	"github.com/riraccuia/pig/pkg/adapter"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/packet"
)

func getAdapter(cfg *config.Config) (common.TunnelAdapter, error) {
	adapterCfg := adapter.AdapterConfig{
		Address:    cfg.TunnelAddress,
		MTU:        cfg.MTU,
		MultiQueue: true,
	}
	return adapter.NewAdapter(adapterCfg)
}

func (s *Server) processInbound(ctx context.Context) {
	for _, q := range s.adapter.(*adapter.TUNAdapter).Queues() {
		pq := make(common.PacketQueue, s.config.QueueSize)
		go s.processInboundQueue(ctx, q, pq)
		s.inbound = append(s.inbound, pq)
	}
}

func (s *Server) getInboundPktQueue() common.PacketQueue {
	queueID := s._next_queue_id.Add(1) % uint64(len(s.inbound))
	return s.inbound[queueID]
}

func (s *Server) readFromAdapter() {
	for _, q := range s.adapter.(*adapter.TUNAdapter).Queues() {
		go s.readFromTunQueue(q)
	}
}

func (s *Server) readFromTunQueue(q io.Reader) {
	for {
		buffer := s.bufferPool.Get().(packet.IPv4Packet)
		n, err := q.Read(buffer)
		if err != nil {
			s.bufferPool.Put(buffer)
			return
		}

		pkt := buffer[:n]
		if pkt.Version() != 4 {
			s.bufferPool.Put(buffer)
			continue
		}

		_client, ok := s.clients.Load(pkt.DestinationIP().String())
		if !ok {
			freeBuf := true
			s.clients.Range(func(key, value any) bool {
				client := value.(*ClientTunnel)
				pkt.Mark(packet.DSCP_MARK_MASQ_SNAT)
				select {
				case client.outbound.C <- buffer:
					freeBuf = false
				default:
				}
				return true
			})
			if freeBuf {
				s.bufferPool.Put(buffer)
			}
			continue
		}
		client := _client.(*ClientTunnel)

		select {
		case client.outbound.C <- buffer:
		default:
			s.bufferPool.Put(buffer)
		}
	}
}

func (s *Server) _readFromTunQueue(q io.Reader) {
	for {
		buffer := s.bufferPool.Get().(packet.IPv4Packet)
		n, err := q.Read(buffer)
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

func (s *Server) processInboundQueue(ctx context.Context, q io.Writer, pq common.PacketQueue) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-pq:
			totalLen := pkt.TotalLength()
			if totalLen > 0 && totalLen <= len(pkt[:totalLen]) {
				q.Write(pkt[:totalLen])
			}
			s.bufferPool.Put(pkt)
		}
	}
}
