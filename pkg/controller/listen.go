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

func (c *Controller) getListenFunc(ctx context.Context, cfg *config.TunnelConfig) (func() (transport.Listener, error), error) {
	switch {
	case cfg.ICE == nil || !cfg.ICE.Enabled:
		return c.getServerListenFunc(ctx, cfg)
	case cfg.ICE != nil && cfg.ICE.Enabled:
		return c.getICEListenFunc(ctx, cfg)
	}
	return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
}

func (c *Controller) getServerListenFunc(ctx context.Context, cfg *config.TunnelConfig) (func() (transport.Listener, error), error) {
	switch cfg.Proto {
	case config.TransportQUIC:
		tlsConfig, err := c.createTLSConfig(config.ModeServer, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return qt.GetServerListenFunc(ctx, c.logger, cfg, tlsConfig), nil
	case config.TransportUDP:
		return udp.GetServerListenFunc(ctx, c.logger, cfg), nil
	case config.TransportTLS:
		tlsConfig, err := c.createTLSConfig(config.ModeServer, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return trtls.GetServerListenFunc(ctx, c.logger, cfg, tlsConfig), nil
	case config.TransportWS:
		tlsConfig, err := c.createTLSConfig(config.ModeServer, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return ws.GetServerListenFunc(ctx, c.logger, cfg, tlsConfig), nil
	case config.TransportICMP:
		return icmp.GetServerListenFunc(ctx, c.logger, cfg), nil
	case config.TransportTLSICMP:
		tlsConfig, err := c.createTLSConfig(config.ModeServer, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return tlsicmp.GetServerListenFunc(ctx, c.logger, cfg, tlsConfig), nil
	case config.TransportDTLS:
		tlsConfig, err := c.createTLSConfig(config.ModeServer, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return dtls.GetServerListenFunc(ctx, c.logger, cfg, tlsConfig), nil
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
	}
}
