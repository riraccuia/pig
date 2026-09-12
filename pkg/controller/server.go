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

func (c *Controller) StartServer() {
	c.Add(1)
	go c.startServer(c.ctx, c.cfg)
}

func (c *Controller) startServer(ctx context.Context, cfg *config.Config) {
	defer c.Done()

	listenTunnels := tunnelsByDirection(cfg, config.TunnelDirectionListen)
	c.logger.Infof("Starting pig listen runtime | Tunnels: %d", len(listenTunnels))

	for _, tunnelCfg := range listenTunnels {
		c.Add(1)
		go c.startServerTunnel(ctx, tunnelCfg)
	}
}

func (c *Controller) startServerTunnel(ctx context.Context, tunnelCfg *config.TunnelConfig) {
	defer c.Done()

	var (
		tunnel        *server.Server
		listener      func(ctx context.Context) (transport.Listener, error)
		authenticator common.Authenticator
	)

	transportStr := "|"
	if tunnelCfg.ICE == nil || !tunnelCfg.ICE.Enabled {
		transportStr = fmt.Sprintf("| Transport:%s |", tunnelCfg.Proto)
	}

	c.logger.Infof("Starting tunnel %s", transportStr)

	if tunnelCfg.ICE != nil && tunnelCfg.ICE.Enabled {
		c.logger.Info("ICE enabled | STUN server: ", tunnelCfg.ICE.STUNAddress, " | MQTT broker: ", tunnelCfg.ICE.Signaling.MQTT.Address)
	}
	if tunnelCfg.Adapter == nil {
		c.logger.Fatalf("Listen tunnel %s requires a dedicated adapter", tunnelCfg.Name)
	}

	authenticator, err := c.createServerAuthenticator(tunnelCfg.Auth)
	if err != nil {
		c.logger.Fatalf("Failed to create authenticator: %v", err)
	}
	listener, err = c.getListenFunc(tunnelCfg)
	if err != nil {
		c.logger.Fatalf("Failed to get server listener: %v", err)
	}
	adapter, err := c.createAdapter(tunnelCfg.Adapter, true)
	if err != nil {
		c.logger.Fatalf("Failed to create adapter: %v", err)
	}
	c.adapters.Store(adapter.Name(), adapter)
	tunnel, err = server.NewWithAdapter(c.logger, tunnelCfg.Adapter, tunnelCfg, adapter, authenticator)
	if err != nil {
		c.logger.Fatalf("Failed to create server: %v", err)
	}
	if err := tunnel.Start(ctx, listener); err != nil {
		c.logger.Fatalf("Failed to start tunnel: %v", err)
	}
}
