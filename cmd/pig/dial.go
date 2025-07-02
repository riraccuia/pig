package main

import (
	"context"
	"fmt"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/transport"
	"github.com/riraccuia/pig/pkg/transport/dtls"
	icmp "github.com/riraccuia/pig/pkg/transport/icmp"
	qt "github.com/riraccuia/pig/pkg/transport/quic-go"
	trtls "github.com/riraccuia/pig/pkg/transport/tls"
	"github.com/riraccuia/pig/pkg/transport/tlsicmp"
	"github.com/riraccuia/pig/pkg/transport/udp"
	"github.com/riraccuia/pig/pkg/transport/ws"
)

func getDialFunc(ctx context.Context, logger *log.Logger, cfg *config.Config) (func() (transport.Conn, error), error) {
	switch {
	case cfg.ICE == nil || !cfg.ICE.Enabled:
		return getClientDialFunc(ctx, logger, cfg)
	case cfg.ICE != nil && cfg.ICE.Enabled:
		return getICEDialFunc(ctx, logger, cfg)
	}
	return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
}

func getClientDialFunc(ctx context.Context, logger *log.Logger, cfg *config.Config) (func() (transport.Conn, error), error) {
	switch cfg.Proto {
	case config.TransportQUIC:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return qt.GetClientDialFunc(ctx, logger, cfg, tlsConfig), nil
	case config.TransportUDP:
		return udp.GetClientDialFunc(ctx, logger, cfg), nil
	case config.TransportTLS:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return trtls.GetClientDialFunc(ctx, logger, cfg, tlsConfig), nil
	case config.TransportWS:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return ws.GetClientDialFunc(ctx, logger, cfg, tlsConfig), nil
	case config.TransportICMP:
		return icmp.GetClientDialFunc(ctx, logger, cfg), nil
	case config.TransportTLSICMP:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return tlsicmp.GetClientDialFunc(ctx, logger, cfg, tlsConfig), nil
	case config.TransportDTLS:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return dtls.GetClientDialFunc(ctx, logger, cfg, tlsConfig), nil
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
	}
}
