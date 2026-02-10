package controller

import (
	"context"
	"fmt"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/server"
	"github.com/riraccuia/pig/pkg/transport"
)

func (c *Controller) StartServer() {
	c.Add(1)
	go c.startServer(c.ctx, c.cfg)
}

func (c *Controller) startServer(ctx context.Context, cfg *config.Config) {
	defer c.Done()
	var (
		tunnel        *server.Server
		listener      func() (transport.Listener, error)
		authenticator common.Authenticator
	)
	transportStr := "|"
	if !cfg.TunnelConfig.ICE.Enabled {
		transportStr = fmt.Sprintf("| Transport:%s |", cfg.TunnelConfig.Proto)
	}

	c.logger.Infof("Starting pig | Mode: %s %s MTU: %d", cfg.Mode, transportStr, cfg.TunnelConfig.MTU)

	if cfg.TunnelConfig.ICE.Enabled {
		c.logger.Info("ICE enabled | STUN server: ", cfg.TunnelConfig.ICE.STUNAddress, " | MQTT broker: ", cfg.TunnelConfig.ICE.Signaling.MQTTBrokerAddress)
	}
	// Create authenticator if configured
	authenticator, err := c.createServerAuthenticator(cfg.TunnelConfig.Auth)
	if err != nil {
		c.logger.Fatalf("Failed to create authenticator: %v", err)
	}
	listener, err = c.getListenFunc(ctx, &cfg.TunnelConfig)
	if err != nil {
		c.logger.Fatalf("Failed to get server listener: %v", err)
	}
	tunnel, err = server.New(c.logger, &cfg.TunnelConfig, authenticator)
	if err != nil {
		c.logger.Fatalf("Failed to create server: %v", err)
	}
	if err := tunnel.Start(ctx, listener); err != nil {
		c.logger.Fatalf("Failed to start tunnel: %v", err)
	}
}
