package main

import (
	"context"
	"fmt"
	"net/http"

	// _ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"

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

func setupPprof(logger *log.Logger) {
	runtime.SetBlockProfileRate(1)
	runtime.SetMutexProfileFraction(1)

	go func() {
		pprofAddr := ":6060"
		logger.Infof("Starting pprof server on %s", pprofAddr)
		if err := http.ListenAndServe(pprofAddr, nil); err != nil {
			logger.Errorf("Failed to start pprof server: %v", err)
		}
	}()
}

func main() {
	var (
		err    error
		ctx    context.Context
		cancel context.CancelFunc
		logger *log.Logger
		cfg    *config.Config
	)

	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	logger = log.NewLogger(ctx)
	transport.Logger = logger

	cfg = parseCmdFlags(logger)

	logger.SetLevel(cfg.LogLevel)

	logger.Infof("Mode: %s, Transport: %s, MTU: %d", cfg.Mode, cfg.Transport, cfg.MTU)

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
		dialer, err = getClientDialFunc(ctx, cfg, logger)
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
		listener, err = getServerListenFunc(ctx, cfg, logger)
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
	default:
		logger.Fatalf("Invalid mode: %s", cfg.Mode)
	}

	if err != nil {
		logger.Fatalf("Failed to create tunnel: %v", err)
	}

	// setupPprof(logger)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
}

func getClientDialFunc(ctx context.Context, cfg *config.Config, logger *log.Logger) (func() (transport.Conn, error), error) {
	switch cfg.Transport {
	case config.TransportQUIC:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return qt.GetClientDialFunc(ctx, cfg, tlsConfig), nil
	case config.TransportUDP:
		return udp.GetClientDialFunc(ctx, cfg), nil
	case config.TransportTLS:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return trtls.GetClientDialFunc(ctx, cfg, tlsConfig), nil
	case config.TransportWS:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return ws.GetClientDialFunc(ctx, cfg, tlsConfig), nil
	case config.TransportICMP:
		return icmp.GetClientDialFunc(ctx, cfg), nil
	case config.TransportTLSICMP:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return tlsicmp.GetClientDialFunc(ctx, cfg, tlsConfig), nil
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Transport)
	}
}

func getServerListenFunc(ctx context.Context, cfg *config.Config, logger *log.Logger) (func() (transport.Listener, error), error) {
	switch cfg.Transport {
	case config.TransportQUIC:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return qt.GetServerListenFunc(ctx, cfg, tlsConfig), nil
	case config.TransportUDP:
		return udp.GetServerListenFunc(ctx, cfg), nil
	case config.TransportTLS:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return trtls.GetServerListenFunc(ctx, cfg, tlsConfig), nil
	case config.TransportWS:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return ws.GetServerListenFunc(ctx, cfg, tlsConfig), nil
	case config.TransportICMP:
		return icmp.GetServerListenFunc(ctx, cfg), nil
	case config.TransportTLSICMP:
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS config: %w", err)
		}
		return tlsicmp.GetServerListenFunc(ctx, cfg, tlsConfig), nil
	default:
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Transport)
	}
}
