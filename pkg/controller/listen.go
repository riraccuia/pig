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

func (c *Controller) getListenFunc(tunnelInfo *TunnelInfo, mtu int) (func(ctx context.Context) (transport.Listener, error), error) {
	cfg := tunnelInfo.Tunnel.Config()
	switch {
	case cfg.ICE != nil && cfg.ICE.Enabled:
		return c.getICEListenFunc(tunnelInfo, mtu)
	default:
		return c.getServerListenFunc(tunnelInfo, mtu)
	}
}

func (c *Controller) getServerListenFunc(tunnelInfo *TunnelInfo, mtu int) (func(ctx context.Context) (transport.Listener, error), error) {
	cfg := tunnelInfo.Tunnel.Config()
	logger := tunnelInfo.Logger

	bindAdapter := ""
	if cfg.Proto == config.TransportICMP || cfg.Proto == config.TransportTLSICMP {
		if cfg.Adapter == nil || cfg.Adapter.BindAdapter == "" {
			return nil, fmt.Errorf("bind adapter required but not configured")
		}
		bindAdapter = cfg.Adapter.BindAdapter
	}

	switch cfg.Proto {
	case config.TransportQUIC:
		tlsConfig, err := c.createTLSConfig(config.TunnelDirectionListen, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return qt.GetServerListenFunc(logger, cfg, tlsConfig), nil
	case config.TransportUDP:
		return udp.GetServerListenFunc(logger, cfg), nil
	case config.TransportTLS:
		tlsConfig, err := c.createTLSConfig(config.TunnelDirectionListen, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return trtls.GetServerListenFunc(logger, cfg, tlsConfig), nil
	case config.TransportWS:
		tlsConfig, err := c.createTLSConfig(config.TunnelDirectionListen, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return ws.GetServerListenFunc(logger, cfg, tlsConfig), nil
	case config.TransportICMP:
		return icmp.GetServerListenFunc(logger, cfg, bindAdapter), nil
	case config.TransportTLSICMP:
		tlsConfig, err := c.createTLSConfig(config.TunnelDirectionListen, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return tlsicmp.GetServerListenFunc(logger, cfg, tlsConfig, bindAdapter), nil
	case config.TransportDTLS:
		tlsConfig, err := c.createTLSConfig(config.TunnelDirectionListen, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return dtls.GetServerListenFunc(logger, cfg, tlsConfig, mtu), nil
	case config.TransportWG:
		return wireguard.GetServerListenFunc(logger, cfg, mtu), nil
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
	}
}
