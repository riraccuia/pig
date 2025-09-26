package main

import (
	"context"
	"fmt"
	"io"

	"github.com/riraccuia/pig/pkg/client"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/server"
	"github.com/riraccuia/pig/pkg/transport"
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

	transportStr := "|"
	if !cfg.ICE.Enabled {
		transportStr = fmt.Sprintf("| Transport:%s |", cfg.Proto)
	}

	logger.Infof("Starting pig | Mode: %s %s MTU: %d", cfg.Mode, transportStr, cfg.MTU)

	if cfg.ICE.Enabled {
		logger.Info("ICE enabled | STUN server: ", cfg.ICE.STUNAddress, " | MQTT broker: ", cfg.ICE.Signaling.MQTTBrokerAddress)
	}

	switch cfg.Mode {
	case "client":
		var (
			tunnel        *client.Client
			dialer        func() (transport.Conn, error)
			authenticator common.Authenticator
		)
		logger.Infof("Resolved target: %s:%d", cfg.Target.Address, cfg.Target.Port)
		// Create authenticator if configured
		authenticator, err = createClientAuthenticator(logger, cfg)
		if err != nil {
			logger.Fatalf("Failed to create authenticator: %v", err)
		}
		dialer, err = getDialFunc(ctx, logger, cfg)
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
		listener, err = getListenFunc(ctx, logger, cfg)
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

	handleGracefulShutdown(ctx, logger, cancel, closer)
}
