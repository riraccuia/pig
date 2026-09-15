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
	"github.com/riraccuia/pig/pkg/transport/ws"
)

func (c *Controller) getListenFunc(cfg *config.TunnelConfig) (func(ctx context.Context) (transport.Listener, error), error) {
	switch {
	case cfg.ICE == nil || !cfg.ICE.Enabled:
		return c.getServerListenFunc(cfg)
	case cfg.ICE != nil && cfg.ICE.Enabled:
		return c.getICEListenFunc(cfg)
	}
	return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
}

func (c *Controller) getServerListenFunc(cfg *config.TunnelConfig) (func(ctx context.Context) (transport.Listener, error), error) {
	switch cfg.Proto {
	case config.TransportQUIC:
		tlsConfig, err := c.createTLSConfig(config.TunnelDirectionListen, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return qt.GetServerListenFunc(c.logger, cfg, tlsConfig), nil
	case config.TransportUDP:
		return udp.GetServerListenFunc(c.logger, cfg), nil
	case config.TransportTLS:
		tlsConfig, err := c.createTLSConfig(config.TunnelDirectionListen, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return trtls.GetServerListenFunc(c.logger, cfg, tlsConfig), nil
	case config.TransportWS:
		tlsConfig, err := c.createTLSConfig(config.TunnelDirectionListen, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return ws.GetServerListenFunc(c.logger, cfg, tlsConfig), nil
	case config.TransportICMP:
		return icmp.GetServerListenFunc(c.logger, cfg, cfg.Adapter.BindAdapter), nil
	case config.TransportTLSICMP:
		tlsConfig, err := c.createTLSConfig(config.TunnelDirectionListen, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return tlsicmp.GetServerListenFunc(c.logger, cfg, tlsConfig, cfg.Adapter.BindAdapter), nil
	case config.TransportDTLS:
		tlsConfig, err := c.createTLSConfig(config.TunnelDirectionListen, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return dtls.GetServerListenFunc(c.logger, cfg, tlsConfig, cfg.Adapter.MTU), nil
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
	}
}
