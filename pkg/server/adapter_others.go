//go:build !linux
// +build !linux

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
	return adapter.NewAdapter(adapter.AdapterConfig{
		Address: cfg.TunnelAddress,
		MTU:     cfg.MTU,
	})
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

func (s *Server) processInbound(ctx context.Context) {
	pq := make(common.PacketQueue, s.config.QueueSize)
	go s.processInboundQueue(ctx, s.adapter, pq)
	s.inbound = append(s.inbound, pq)
}

func (s *Server) getInboundPktQueue() common.PacketQueue {
	return s.inbound[0]
}

func (s *Server) processInboundQueue(ctx context.Context, q io.Writer, pq common.PacketQueue) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-pq:
			totalLen := pkt.TotalLength()
			if totalLen > 0 && totalLen <= len(pkt[:totalLen]) {
				_, err := q.Write(pkt[:totalLen])
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
