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

//go:build !linux

package server

import (
	"context"
	"io"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/queue"
)

func (s *Server) readFromAdapter(ctx context.Context) {
	for {
		if common.IsContextDone(ctx) {
			return
		}
		buffer := s.bufferPool.Get().([]byte)
		n, err := s.adapter.Read(buffer)
		if err != nil {
			s.bufferPool.Put(buffer)
			return
		}

		var pkt network.IPPacket
		switch network.IPv4Packet(buffer[:n]).Version() {
		case 4:
			pkt = network.IPv4Packet(buffer[:n])
		case 6:
			pkt = network.IPv6Packet(buffer[:n])
			s.bufferPool.Put(buffer)
			continue
		}

		select {
		case s.outbound <- pkt:
		default:
			s.bufferPool.Put(buffer)
		}
	}
}

func (s *Server) processInbound(ctx context.Context) {
	pq := make(common.PacketQueue, s.adapterCfg.QueueSize)
	s.inbound = append(s.inbound, pq)
	s.processInboundQueue(ctx, s.adapter, pq)
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
			if totalLen > 0 && totalLen <= len(pkt.Bytes()[:totalLen]) {
				_, err := q.Write(pkt.Bytes()[:totalLen])
				s.bufferPool.Put(pkt.Bytes())
				if err != nil {
					continue
				}
			} else {
				s.bufferPool.Put(pkt.Bytes())
			}
		}
	}
}

func (s *Server) processOutbound(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-s.outbound:
			if !ok {
				return
			}
			_client, ok := s.clients.Load(pkt.DestinationIP().String())
			if !ok {
				s.bufferPool.Put(pkt.Bytes())
				continue
			}
			client := _client.(*ClientTunnel)

			err := client.outbound.Push(pkt)
			if err == queue.ErrWREDDropped || err == queue.ErrDropped {
				client.dropLogger.Incr(1, uint64(pkt.TotalLength()))
				s.bufferPool.Put(pkt.Bytes())
				continue
			}
			if err != nil {
				s.bufferPool.Put(pkt.Bytes())
				continue
			}
		}
	}
}
