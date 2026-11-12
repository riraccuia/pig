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

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/server"
	"github.com/riraccuia/pig/pkg/transport"
)

func (c *Controller) startServer(ctx context.Context) {
	c.doStartServer(ctx, c.cfg)
}

func (c *Controller) doStartServer(ctx context.Context, cfg *config.Config) {
	if !cfg.HasListenTunnels() {
		return
	}

	listenTunnels := tunnelsByDirection(cfg, config.TunnelDirectionListen)
	c.logger.Infof("Starting pig listen runtime | Listeners: %d", len(listenTunnels))

	for _, tunnelCfg := range listenTunnels {
		c.tunnelsWg.Go(func() {
			c.startServerTunnel(ctx, tunnelCfg)
		})
	}
}

func (c *Controller) startServerTunnel(ctx context.Context, tunnelCfg *config.TunnelConfig) {
	var (
		tunnel        *server.Server
		listener      func(ctx context.Context) (transport.Listener, error)
		authenticator common.Authenticator
	)

	logger := c.logger.WithFields([]common.LoggerField{
		{
			Key:   "tunnel",
			Value: tunnelCfg.Name,
		},
	})

	transportStr := ""
	if tunnelCfg.ICE == nil || !tunnelCfg.ICE.Enabled {
		transportStr += fmt.Sprintf(" | Transport:%s", tunnelCfg.Proto)
	}

	logger.Infof("New listener %s", transportStr)

	if tunnelCfg.ICE != nil && tunnelCfg.ICE.Enabled {
		logger.Info("ICE enabled | STUN server: ", tunnelCfg.ICE.STUNAddress, " | MQTT broker: ", tunnelCfg.ICE.Signaling.MQTT.Address)
	}
	if tunnelCfg.Adapter == nil {
		logger.Fatal("Listener requires a dedicated adapter")
	}

	authenticator, err := c.createServerAuthenticator(tunnelCfg.Auth)
	if err != nil {
		logger.Fatalf("Failed to create authenticator: %v", err)
	}
	adapter, err := c.createAdapter(tunnelCfg.Adapter, true)
	if err != nil {
		logger.Fatalf("Failed to create adapter: %v", err)
	}
	c.adapters.Store(adapter.Name(), adapter)
	tunnel, err = server.NewWithAdapter(logger, tunnelCfg.Adapter, tunnelCfg, adapter, authenticator)
	if err != nil {
		c.logger.Fatalf("Failed to create server: %v", err)
	}
	tunnelInfo := &TunnelInfo{
		Logger: logger,
		Tunnel: tunnel,
	}
	if err := c.StoreTunnelInfo(tunnelInfo); err != nil {
		logger.Errorf("Failed to store tunnel info: %v", err)
		return
	}
	listener, err = c.getListenFunc(tunnelInfo, adapter.MTU())
	if err != nil {
		logger.Errorf("Failed to get server listener: %v", err)
		return
	}
	if err := tunnel.Start(ctx, listener); err != nil {
		logger.Errorf("Failed to start: %v", err)
		return
	}
	tunnel.Wait()
}
