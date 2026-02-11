package client

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/adapter"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/network"
)

func getAdapter(cfg *config.TunnelConfig) (common.TunnelAdapter, error) {
	adapterCfg := adapter.AdapterConfig{
		Address: cfg.TunnelAddress,
		MTU:     cfg.MTU,
	}
	return adapter.NewAdapter(adapterCfg)
}

func (c *Client) readFromAdapter(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.done:
			// in its current state, this channel will not receive on a reconnect attempt
			// because the adapter.Read below will likely block until the connection is established
			// also the current logic will recreate the done channel, rendering this check useless
			// TODO: improve this
			return
		default:
			pkt := c.bufferPool.Get().(network.IPv4Packet)
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
		case pkt, ok := <-c.inbound:
			if !ok {
				return
			}
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

func getMasqAddress(ipNetStr string) (net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(ipNetStr)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IP net: %w", err)
	}
	// get the next ip in the subnet
	ipInt := binary.BigEndian.Uint32(ip.To4())
	ipInt++
	nextIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(nextIP, ipInt)
	// check if the next ip is in the subnet
	if !ipNet.Contains(nextIP) {
		return nil, fmt.Errorf("no more IPs in subnet")
	}
	return nextIP, nil
}
