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
	"errors"
	"fmt"
	"io"

	"github.com/riraccuia/pig/pkg/adapter"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/queue"
)

func (s *Server) processInbound(ctx context.Context) {
	var queues []io.ReadWriteCloser
	switch a := s.adapter.(type) {
	case *adapter.TUNAdapter:
		queues = a.Queues()
	default:
		queues = append(queues, s.adapter)
	}
	for _, q := range queues {
		pq := make(common.PacketQueue, s.adapterCfg.QueueSize)
		go s.processInboundQueue(ctx, q, pq)
		s.inbound = append(s.inbound, pq)
	}
}

func (s *Server) getInboundPktQueue() common.PacketQueue {
	queueID := s._next_queue_id.Add(1) % uint64(len(s.inbound))
	return s.inbound[queueID]
}

func (s *Server) readFromAdapter(ctx context.Context) {
	var queues []io.ReadWriteCloser
	switch a := s.adapter.(type) {
	case *adapter.TUNAdapter:
		queues = a.Queues()
	default:
		queues = append(queues, s.adapter)
	}
	for _, q := range queues {
		s.wg.Go(func() { s.readFromTunQueue(ctx, q) })
	}
}

func (s *Server) readFromTunQueue(ctx context.Context, q io.Reader) {
	bufferSize := s.adapter.MTU()

	for {
		if common.IsContextDone(ctx) {
			return
		}

		buffer := s.bufferPool.GetBuffer(bufferSize)
		n, err := q.Read(buffer)
		if err != nil {
			if errors.Is(err, io.EOF) {
				err = fmt.Errorf("adapter %s closed (%w)", s.adapter.Name(), err)
			}
			select {
			case s.sigError <- err:
			default:
			}
			s.bufferPool.PutBuffer(buffer)
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
			s.bufferPool.PutBuffer(buffer)
			continue
		}
		client := _client.(*ClientTunnel)

		err = client.outbound.Push(pkt)
		if err == queue.ErrWREDDropped || err == queue.ErrDropped {
			client.dropLogger.Incr(1, uint64(pkt.TotalLength()))
			s.bufferPool.PutBuffer(buffer)
			continue
		}
		if err != nil {
			s.bufferPool.PutBuffer(buffer)
			continue
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
			s.bufferPool.PutBuffer(pkt.Bytes())
		}
	}
}

func (s *Server) processOutbound(ctx context.Context) {
	// processOutbound is a no-op on Linux
}
