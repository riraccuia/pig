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
	"runtime"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/network"
)

func (s *Server) readFromAdapter() {
	go s.processOutbound(context.Background())
	runtime.Gosched()
	for {
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
