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

//go:build linux

package server

import (
	"context"
	"io"

	"github.com/riraccuia/pig/pkg/adapter"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/network"
)

func (s *Server) processInbound(ctx context.Context) {
	for _, q := range s.adapter.(*adapter.TUNAdapter).Queues() {
		pq := make(common.PacketQueue, s.adapterCfg.QueueSize)
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
		buffer := s.bufferPool.Get().([]byte)
		n, err := q.Read(buffer)
		if err != nil {
			s.bufferPool.Put(buffer)
			return
		}

		var pkt network.IPPacket
		switch network.IPv4Packet(buffer[:n]).Version() {
		case 4:
			pkt = network.IPv4Packet(buffer[:])
		case 6:
			pkt = network.IPv6Packet(buffer[:])
		}

		_client, ok := s.clients.Load(pkt.DestinationIP().String())
		if !ok {
			freeBuf := true
			s.clients.Range(func(key, value any) bool {
				client := value.(*ClientTunnel)
				if v4Pkt, ok := pkt.(network.IPv4Packet); ok {
					v4Pkt.Mark(network.DSCP_MARK_MASQ_SNAT)
				}
				select {
				case client.outbound.C <- pkt:
					freeBuf = false
					return false
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
		case client.outbound.C <- pkt:
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
			if totalLen > 0 && totalLen <= len(pkt.Bytes()) {
				q.Write(pkt.Bytes()[:totalLen])
			}
			s.bufferPool.Put(pkt.Bytes())
		}
	}
}
