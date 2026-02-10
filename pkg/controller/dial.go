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

func (c *Controller) getDialFunc(ctx context.Context, cfg *config.TunnelConfig) (func() (transport.Conn, error), error) {
	switch {
	case cfg.ICE == nil || !cfg.ICE.Enabled:
		return c.getClientDialFunc(ctx, cfg)
	case cfg.ICE != nil && cfg.ICE.Enabled:
		return c.getICEDialFunc(ctx, cfg)
	}
	return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
}

func (c *Controller) getClientDialFunc(ctx context.Context, cfg *config.TunnelConfig) (func() (transport.Conn, error), error) {
	switch cfg.Proto {
	case config.TransportQUIC:
		tlsConfig, err := c.createTLSConfig(config.ModeClient, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return qt.GetClientDialFunc(ctx, c.logger, cfg, tlsConfig), nil
	case config.TransportUDP:
		return udp.GetClientDialFunc(ctx, c.logger, cfg), nil
	case config.TransportTLS:
		tlsConfig, err := c.createTLSConfig(config.ModeClient, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return trtls.GetClientDialFunc(ctx, c.logger, cfg, tlsConfig), nil
	case config.TransportWS:
		tlsConfig, err := c.createTLSConfig(config.ModeClient, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return ws.GetClientDialFunc(ctx, c.logger, cfg, tlsConfig), nil
	case config.TransportICMP:
		return icmp.GetClientDialFunc(ctx, c.logger, cfg), nil
	case config.TransportTLSICMP:
		tlsConfig, err := c.createTLSConfig(config.ModeClient, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return tlsicmp.GetClientDialFunc(ctx, c.logger, cfg, tlsConfig), nil
	case config.TransportDTLS:
		tlsConfig, err := c.createTLSConfig(config.ModeClient, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return dtls.GetClientDialFunc(ctx, c.logger, cfg, tlsConfig), nil
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
	}
}
