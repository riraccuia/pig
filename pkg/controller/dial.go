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

package controller

import (
	"context"
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/transport"
	"github.com/riraccuia/pig/pkg/transport/dtls"
	icmp "github.com/riraccuia/pig/pkg/transport/icmp"
	qt "github.com/riraccuia/pig/pkg/transport/quic-go"
	trtls "github.com/riraccuia/pig/pkg/transport/tls"
	"github.com/riraccuia/pig/pkg/transport/tlsicmp"
	"github.com/riraccuia/pig/pkg/transport/udp"
	"github.com/riraccuia/pig/pkg/transport/wireguard"
	"github.com/riraccuia/pig/pkg/transport/ws"
)

func (c *Controller) getDialFunc(tunnelInfo *TunnelInfo, mtu int) (func(ctx context.Context) (transport.Conn, error), error) {
	cfg := tunnelInfo.Tunnel.Config()
	switch {
	case cfg.ICE == nil || !cfg.ICE.Enabled:
		return c.getClientDialFunc(tunnelInfo, mtu)
	case cfg.ICE != nil && cfg.ICE.Enabled:
		return c.getICEDialFunc(tunnelInfo, mtu)
	}
	return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
}

func (c *Controller) getClientDialFunc(tunnelInfo *TunnelInfo, mtu int) (func(ctx context.Context) (transport.Conn, error), error) {
	cfg := tunnelInfo.Tunnel.Config()
	targetAddr := cfg.Connect.Address
	logger := tunnelInfo.Logger

	return func(ctx context.Context) (transport.Conn, error) {
		tunnelAddr, err := net.ResolveIPAddr("ip", targetAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve %s address: %w", cfg.Name, err)
		}

		cfg.Connect.Address = tunnelAddr.String()

		tunnelInfo.NewActiveRoute(c.bypassTarget(tunnelInfo.Logger, tunnelAddr.IP))

		switch cfg.Proto {
		case config.TransportQUIC:
			tlsConfig, err := c.createTLSConfig(config.TunnelDirectionConnect, cfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create TLS config: %w", err)
			}
			return qt.GetClientDialFunc(logger, cfg, tlsConfig)(ctx)
		case config.TransportUDP:
			return udp.GetClientDialFunc(logger, cfg)(ctx)
		case config.TransportTLS:
			tlsConfig, err := c.createTLSConfig(config.TunnelDirectionConnect, cfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create TLS config: %w", err)
			}
			return trtls.GetClientDialFunc(logger, cfg, tlsConfig)(ctx)
		case config.TransportWS:
			tlsConfig, err := c.createTLSConfig(config.TunnelDirectionConnect, cfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create TLS config: %w", err)
			}
			return ws.GetClientDialFunc(logger, cfg, tlsConfig)(ctx)
		case config.TransportICMP:
			return icmp.GetClientDialFunc(logger, cfg, cfg.Adapter.BindAdapter)(ctx)
		case config.TransportTLSICMP:
			tlsConfig, err := c.createTLSConfig(config.TunnelDirectionConnect, cfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create TLS config: %w", err)
			}
			return tlsicmp.GetClientDialFunc(logger, cfg, tlsConfig, cfg.Adapter.BindAdapter)(ctx)
		case config.TransportDTLS:
			tlsConfig, err := c.createTLSConfig(config.TunnelDirectionConnect, cfg)
			if err != nil {
				return nil, fmt.Errorf("failed to create TLS config: %w", err)
			}
			return dtls.GetClientDialFunc(logger, cfg, tlsConfig, mtu)(ctx)
		case config.TransportWG:
			return wireguard.GetClientDialFunc(logger, cfg, mtu)(ctx)
		default:
			return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
		}
	}, nil
}
