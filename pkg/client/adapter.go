package client

import (
	"context"

	"github.com/riraccuia/pig/pkg/packet"
)

func (c *Client) readFromAdapter(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		default:
			pkt := c.bufferPool.Get().(packet.IPv4Packet)
			_, err := c.adapter.Read(pkt[:])
			if err != nil {
				c.bufferPool.Put(pkt)
				c.logger.Errorf("failed to read from adapter: %v", err)
				c.Close()
				return
			}
			if pkt.Version() != 4 {
				c.bufferPool.Put(pkt)
				continue
			}

			select {
			case c.outbound.C <- pkt:
			default:
				c.logger.Errorf("client outbound channel full, dropping packet")
				c.bufferPool.Put(pkt)
			}
		}
	}
}

func (c *Client) writeToAdapter(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			return
		case pkt := <-c.inbound:
			totalLen := pkt.TotalLength()
			if pkt.Version() != 4 {
				c.logger.Errorf("received non-IPv4 packet, dropping")
				c.bufferPool.Put(pkt)
				continue
			}
			_, err := c.adapter.Write(pkt[:totalLen])
			c.bufferPool.Put(pkt)
			if err != nil {
				c.logger.Errorf("failed to write to adapter: %v", err)
				c.Close()
				return
			}
		}
	}
}
