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
	"time"

	"github.com/riraccuia/pig/pkg/client"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/demux"
	"github.com/riraccuia/pig/pkg/script"
	"github.com/riraccuia/pig/pkg/transport"
)

func (c *Controller) StartClient() {
	c.Add(1)
	go c.startClient(c.ctx, c.cfg)
}

func (c *Controller) startClient(ctx context.Context, cfg *config.Config) {
	defer c.Done()

	adapterCfg := &cfg.Adapter
	connectTunnels := tunnelsByDirection(cfg, config.TunnelDirectionConnect)

	c.logger.Infof("Starting pig connect runtime | MTU: %d | Tunnels: %d", adapterCfg.MTU, len(connectTunnels))

	c.scriptExecutor = script.New(c.logger, cfg.ScriptPath)

	c.routeRequests = make(chan routeRequest, 16)

	if err := c.setupClientAdapter(ctx, adapterCfg); err != nil {
		c.logger.Fatalf("Failed to setup adapter: %v", err)
	}

	// Central route manager goroutine: installs global routes once, then
	// processes per-tunnel add/remove requests for the controller lifetime.
	c.Add(1)
	go c.manageRoutes(ctx, cfg)

	for _, tunnelCfg := range connectTunnels {
		if err := c.AddClientTunnel(ctx, tunnelCfg); err != nil {
			c.logger.Fatalf("Failed to add client tunnel: %v", err)
		}
	}
}

// setupClientAdapter creates the adapter and starts the reader goroutine that dispatches
// packets via the demux. Must be called after demux is initialized.
func (c *Controller) setupClientAdapter(ctx context.Context, cfg *config.AdapterConfig) error {
	adapter, err := c.createAdapter(cfg, false)
	if err != nil {
		return err
	}
	c.clientAdapter = adapter
	c.adapters.Store(adapter.Name(), adapter)
	c.demux = demux.New(c.logger, c.clientAdapter, cfg.MTU).WithBufferPool(c.bufferPool)
	go c.demux.Start(ctx)
	return nil
}

// AddClientTunnel creates and starts a client tunnel from the given config.
// It can be called after StartClient to attach additional tunnels at runtime
// (e.g. when a control plane pushes new peer configurations).
func (c *Controller) AddClientTunnel(ctx context.Context, tunnelCfg *config.TunnelConfig) error {
	if tunnelCfg.Direction != config.TunnelDirectionConnect {
		return fmt.Errorf("tunnel %s is not a connect tunnel", tunnelCfg.Name)
	}
	if c.clientAdapter == nil {
		return fmt.Errorf("adapter not initialized; call StartClient first")
	}
	if c.demux == nil {
		return fmt.Errorf("demux not initialized; call StartClient first")
	}

	ta := c.demux.NewAdapter(ctx, 1024)
	tunnel, dialer, err := c.newClientTunnel(ctx, tunnelCfg, ta)
	if err != nil {
		return err
	}

	c.tunnels.Store(tunnelCfg.Name, tunnel)
	c.Add(1)
	go c.runClientTunnel(ctx, tunnel, dialer)

	return nil
}

func (c *Controller) newClientTunnel(ctx context.Context, tunnelCfg *config.TunnelConfig, ta *demux.Adapter) (*client.Client, func(ctx context.Context) (transport.Conn, error), error) {
	transportStr := "|"
	if tunnelCfg.ICE == nil || !tunnelCfg.ICE.Enabled {
		transportStr = fmt.Sprintf("| Transport:%s |", tunnelCfg.Proto)
	}
	c.logger.Infof("Adding tunnel %s Target: %s:%d", transportStr, tunnelCfg.Connect.Address, tunnelCfg.Connect.Port)

	authenticator, err := c.createClientAuthenticator(tunnelCfg.Auth)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	dialer, err := c.getDialFunc(ctx, tunnelCfg)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create dialer: %w", err)
	}

	tunnel, err := client.NewWithAdapter(c.logger, &c.cfg.Adapter, tunnelCfg, ta, authenticator)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create client: %w", err)
	}

	return tunnel.WithBufferPool(c.bufferPool), dialer, nil
}

func (c *Controller) runClientTunnel(ctx context.Context, tunnel *client.Client, dialer func(ctx context.Context) (transport.Conn, error)) {
	defer c.Done()

	c.handleClientEventsAsync(ctx, tunnel)

	t := time.NewTimer(time.Millisecond)
	for {
		select {
		case <-t.C:
		case <-ctx.Done():
			c.logger.Debugf("Controller exiting, client tunnel stopped")
			return
		}
		if err := tunnel.Start(ctx, dialer); err != nil {
			c.logger.Fatalf("Failed to start tunnel: %v", err)
		}
		tunnel.WaitClose()
		t.Reset(time.Second)
	}
}
