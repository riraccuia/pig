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

func getListenFunc(ctx context.Context, logger *log.Logger, cfg *config.Config) (func() (transport.Listener, error), error) {
	switch {
	case cfg.ICE == nil || !cfg.ICE.Enabled:
		return getServerListenFunc(ctx, logger, cfg)
	case cfg.ICE != nil && cfg.ICE.Enabled:
		return getICEListenFunc(ctx, logger, cfg)
	}
	return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
}

func getServerListenFunc(ctx context.Context, logger *log.Logger, cfg *config.Config) (func() (transport.Listener, error), error) {
	switch cfg.Proto {
	case config.TransportQUIC:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return qt.GetServerListenFunc(ctx, logger, cfg, tlsConfig), nil
	case config.TransportUDP:
		return udp.GetServerListenFunc(ctx, logger, cfg), nil
	case config.TransportTLS:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return trtls.GetServerListenFunc(ctx, logger, cfg, tlsConfig), nil
	case config.TransportWS:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return ws.GetServerListenFunc(ctx, logger, cfg, tlsConfig), nil
	case config.TransportICMP:
		return icmp.GetServerListenFunc(ctx, logger, cfg), nil
	case config.TransportTLSICMP:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return tlsicmp.GetServerListenFunc(ctx, logger, cfg, tlsConfig), nil
	case config.TransportDTLS:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return dtls.GetServerListenFunc(ctx, logger, cfg, tlsConfig), nil
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
	}
}
