package main

import (
	"context"
	"fmt"
	"io"

	"os"
	"os/signal"

	"github.com/riraccuia/pig/pkg/client"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/server"
	"github.com/riraccuia/pig/pkg/transport"
	icmp "github.com/riraccuia/pig/pkg/transport/icmp"
	qt "github.com/riraccuia/pig/pkg/transport/quic-go"
	trtls "github.com/riraccuia/pig/pkg/transport/tls"
	"github.com/riraccuia/pig/pkg/transport/tlsicmp"
	"github.com/riraccuia/pig/pkg/transport/udp"
	"github.com/riraccuia/pig/pkg/transport/ws"
)

func pig(mo config.Mode) {
	var (
		err    error
		ctx    context.Context
		cancel context.CancelFunc
		logger *log.Logger
		cfg    *config.Config
		closer io.Closer
	)

	cfg, logger = initPig(mo)

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	logger.Infof("Starting pig | Mode: %s | Transport: %s | MTU: %d", cfg.Mode, cfg.Proto, cfg.MTU)

	if cfg.ICE != nil && cfg.ICE.Enabled {
		logger.Info("ICE enabled | STUN server: ", cfg.ICE.STUNAddress, " | MQTT broker: ", cfg.ICE.Signaling.MQTTBrokerAddress)
	}

	switch cfg.Mode {
	case "client":
		var (
			tunnel        *client.Client
			dialer        func() (transport.Conn, error)
			authenticator common.Authenticator
		)
		// Create authenticator if configured
		authenticator, err = createClientAuthenticator(logger, cfg)
		if err != nil {
			logger.Fatalf("Failed to create authenticator: %v", err)
		}
		dialer, err = getClientDialFunc(ctx, logger, cfg)
		if err != nil {
			logger.Fatalf("Failed to get client dialer: %v", err)
		}
		tunnel, err = client.New(logger, cfg, authenticator)
		if err != nil {
			break
		}
		if err := tunnel.Start(ctx, dialer); err != nil {
			logger.Fatalf("Failed to start tunnel: %v", err)
		}
		closer = tunnel
	case "server":
		var (
			tunnel        *server.Server
			listener      func() (transport.Listener, error)
			authenticator common.Authenticator
		)
		// Create authenticator if configured
		authenticator, err = createServerAuthenticator(logger, cfg)
		if err != nil {
			logger.Fatalf("Failed to create authenticator: %v", err)
		}
		listener, err = getServerListenFunc(ctx, logger, cfg)
		if err != nil {
			logger.Fatalf("Failed to get server listener: %v", err)
		}
		tunnel, err = server.New(logger, cfg, authenticator)
		if err != nil {
			break
		}
		if err := tunnel.Start(ctx, listener); err != nil {
			logger.Fatalf("Failed to start tunnel: %v", err)
		}
		closer = tunnel
	default:
		logger.Fatalf("Invalid mode: %s", cfg.Mode)
	}

	if err != nil {
		logger.Fatalf("Failed to create tunnel: %v", err)
	}

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	<-sigChan
	logger.Infof("Received signal: %v", <-sigChan)
	closer.Close()
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
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
	}
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
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
	}
}
