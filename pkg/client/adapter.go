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

package client

import (
	"context"
	"fmt"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/network"
)

func (c *Client) readFromAdapter(ctx context.Context) {
	_, isOutQueuer := c.adapter.(OutQueuer)
	if isOutQueuer {
		c.readFromAdapterOutQueue(ctx)
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		default:
			buf := c.bufferPool.GetBuffer(c.mtu)
			_, err := c.adapter.Read(buf[:])
			if err != nil {
				c.bufferPool.PutBuffer(buf)
				c.logger.Errorf("failed to read from adapter: %v", err)
				select {
				case c.connError <- fmt.Errorf("failed to read from adapter: %w", err):
				default:
				}
				return
			}

			var pkt network.IPPacket

			switch network.IPv4Packet(buf[:]).Version() {
			case 4:
				pkt = network.IPv4Packet(buf[:])
			case 6:
				pkt = network.IPv6Packet(buf[:])
			}

			if c.outbound.IsDrop() {
				c.dropLogger.Incr(1, uint64(pkt.TotalLength()))
				c.bufferPool.PutBuffer(buf)
				continue
			}

			select {
			case c.outbound.C <- pkt:
			default:
				c.logger.Errorf("client outbound channel full, dropping packet")
				c.bufferPool.PutBuffer(buf)
			}
		}
	}
}

func (c *Client) writeToAdapter(ctx context.Context) {
	_, isInQueuer := c.adapter.(InQueuer)
	if isInQueuer {
		c.writeToAdapterInQueue(ctx)
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case pkt, ok := <-c.inbound:
			if !ok {
				return
			}
			totalLen := pkt.TotalLength()
			_, err := c.adapter.Write(pkt.Bytes()[:totalLen])
			c.bufferPool.PutBuffer(pkt.Bytes())
			if err != nil {
				c.logger.Errorf("failed to write to adapter: %v", err)
				select {
				case c.connError <- fmt.Errorf("failed to write to adapter: %w", err):
				default:
				}
				return
			}
		}
	}
}

type OutQueuer interface {
	OutQueue() (common.PacketQueue, error)
}

func (c *Client) readFromAdapterOutQueue(ctx context.Context) {
	outQueue, err := c.adapter.(OutQueuer).OutQueue()
	if err != nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case pkt := <-outQueue:
			if c.outbound.IsDrop() {
				c.dropLogger.Incr(1, uint64(pkt.TotalLength()))
				c.bufferPool.PutBuffer(pkt.Bytes())
				continue
			}

			select {
			case c.outbound.C <- pkt:
			default:
				c.bufferPool.PutBuffer(pkt.Bytes())
			}
		}
	}
}

type InQueuer interface {
	InQueue() (common.PacketQueue, error)
}

func (c *Client) writeToAdapterInQueue(ctx context.Context) {
	inQueue, err := c.adapter.(InQueuer).InQueue()
	if err != nil {
		return
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case pkt := <-c.inbound:
			/*if pkt.Version() != 4 {
				c.bufferPool.PutBuffer(pkt.Bytes())
				continue
			}*/
			select {
			case inQueue <- pkt:
			default:
				c.logger.Errorf("adapter inbound channel full, dropping packet")
				c.bufferPool.PutBuffer(pkt.Bytes())
			}
		}
	}
}
