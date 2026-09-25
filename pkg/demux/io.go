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

package demux

import (
	"context"

	"github.com/riraccuia/pig/pkg/network"
)

// readFromAdapter reads packets from the adapter and writes them to the outbound channel
// we need to read as fast as possible to avoid blocking the adapter.
func (d *Demux) readFromAdapter(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		buf := d.bufferPool.GetBuffer(d.mtu)
		_, err := d.adapter.Read(buf[:])
		if err != nil {
			d.bufferPool.PutBuffer(buf)
			d.logger.Errorf("demux failed to read from adapter %s: %v", d.adapter.Name(), err)
			return
		}

		var pkt network.IPPacket

		switch network.IPv4Packet(buf[:]).Version() {
		case 4:
			pkt = network.IPv4Packet(buf[:])
		case 6:
			pkt = network.IPv6Packet(buf[:])
		}

		select {
		case d.outbound <- pkt:
		default:
			d.logger.Errorf("demux outbound channel full, dropping packet")
			d.bufferPool.PutBuffer(pkt.Bytes())
		}
	}
}

// writeToAdapter writes packets to the adapter from the inbound channel
// the demux adapters will write packets to the inbound channel.
// This method reduces pressure on the adapter since it will be the only routine
// writing to it.
func (d *Demux) writeToAdapter(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-d.inbound:
			if !ok {
				return
			}
			_, err := d.adapter.Write(pkt.Bytes()[:pkt.TotalLength()])
			d.bufferPool.PutBuffer(pkt.Bytes())
			if err != nil {
				d.logger.Errorf("demux failed to write to adapter %s: %v", d.adapter.Name(), err)
			}
		}
	}
}

// readFromOutbound reads packets from the outbound channel and dispatches them to the
// appropriate demux adapter based on the pseudo routing table.
func (d *Demux) readFromOutbound(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt, ok := <-d.outbound:
			if !ok {
				return
			}
			targetAdapter := d.routeTable.lookup(pkt.DestinationIP())
			if targetAdapter == nil {
				d.bufferPool.PutBuffer(pkt.Bytes())
				continue
			}
			select {
			case targetAdapter.outqueue <- pkt:
			default:
				d.logger.Errorf("demux out queue full, dropping packet")
				d.bufferPool.PutBuffer(pkt.Bytes())
			}
		}
	}
}
