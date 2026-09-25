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

package server

import (
	"context"
	"io"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/transport"
)

// acceptStreams handles incoming stream connections from the QUIC transport.
func (client *ClientTunnel) acceptStreams(ctx context.Context) {
	for {
		if common.IsContextDone(ctx) {
			return
		}

		stream, err := client.conn.AcceptStream(ctx)
		if err != nil {
			select {
			case client.connError <- err:
			default:
			}
			return
		}

		client.logger.Debugf("accepted stream from client %s", client.conn.RemoteAddr())

		stream.Flush()
		client.streams.Add(stream)

		go client.handleStream(ctx, stream)
	}
}

func (client *ClientTunnel) handleStream(ctx context.Context, stream transport.Stream) {
	defer func() {
		client.streams.Remove(stream)
		stream.Close()
	}()
	client.handleInbound(ctx, stream)
}

func (client *ClientTunnel) handleOutbound(ctx context.Context) {
	if client.conn.IsStreamed() {
		client.handleOutboundStream(ctx)
		return
	}
	client.handleOutboundConn(ctx)
}

func (client *ClientTunnel) handleOutboundConn(ctx context.Context) {
	// Create a buffer to hold multiple packets
	const maxBatchSize = 64 * 1024 // 64KB batch size
	buffer := make([]byte, 0, maxBatchSize)
	batch := buffer[:0]

	// Helper function to write and reset batch
	writeBatch := func() error {
		for len(batch) > 0 {
			n, err := client.conn.Write(batch)
			batch = batch[n:]
			if err != nil && err != io.ErrShortWrite {
				client.logger.Errorf("failed to write outbound data to connection: %v", err)
				return err
			}
		}
		batch = buffer[:0]
		return nil
	}

	processPacket := func(pkt network.IPPacket) error {
		totalLen := pkt.TotalLength()
		if totalLen <= 0 || totalLen > len(pkt.Bytes()) {
			client.logger.Debugf("outbound packet with invalid length: %d", totalLen)
			client.parent.bufferPool.Put(pkt.Bytes())
			return nil
		}

		// If adding this packet would exceed batch size, flush current batch first
		if len(batch)+totalLen > maxBatchSize {
			if err := writeBatch(); err != nil {
				client.parent.bufferPool.Put(pkt.Bytes())
				return err
			}
		}

		// Append packet to batch
		batch = append(batch, pkt.Bytes()[:totalLen]...)
		client.parent.bufferPool.Put(pkt.Bytes())

		// If batch is full, write immediately
		if len(batch) >= maxBatchSize {
			if err := writeBatch(); err != nil {
				client.parent.bufferPool.Put(pkt.Bytes())
				return err
			}
		}
		return nil
	}

	for {
		if common.IsContextDone(ctx) {
			return
		}

		pkts, empty, closed := client.outbound.TryPopAll()
		if closed {
			if empty {
				return
			}
			for _, pkt := range pkts {
				client.parent.bufferPool.Put(pkt.Bytes())
			}
			return
		}
		if empty {
			if err := writeBatch(); err != nil {
				client.logger.Error(err)
				return
			}
			pkts = client.outbound.PopAll()
		}
		if pkts == nil {
			return
		}
		for _, pkt := range pkts {
			if err := processPacket(pkt); err != nil {
				client.logger.Debugf("failed to process packet: %v", err)
				return
			}
		}
	}
}

func (client *ClientTunnel) handleOutboundStream(ctx context.Context) {
	for {
		if common.IsContextDone(ctx) {
			return
		}

		pkts, empty, closed := client.outbound.TryPopAll()
		if closed {
			if empty {
				return
			}
			for _, pkt := range pkts {
				client.parent.bufferPool.Put(pkt.Bytes())
			}
			return
		}
		if empty {
			pkts = client.outbound.PopAll()
		}
		if pkts == nil {
			return
		}

		for _, pkt := range pkts {
			totalLen := pkt.TotalLength()
			if totalLen <= 0 || totalLen > len(pkt.Bytes()) {
				client.parent.bufferPool.Put(pkt.Bytes())
				continue
			}

			stream := client.streams.SelectByIPAndPort(pkt.SourceIP(), pkt.SourcePort())
			if stream == nil {
				client.logger.Infof("no stream found for client %s", client.conn.RemoteAddr())
				client.parent.bufferPool.Put(pkt.Bytes())
				continue
			}
			_, err := stream.Write(pkt.Bytes()[:totalLen])
			stream.Flush()
			client.parent.bufferPool.Put(pkt.Bytes())
			if err != nil {
				return
			}
		}
	}
}
