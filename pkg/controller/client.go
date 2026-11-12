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
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/demux"
	"github.com/riraccuia/pig/pkg/script"
	"github.com/riraccuia/pig/pkg/transport"
)

func (c *Controller) startClient(ctx context.Context) {
	c.doStartClient(ctx, c.cfg)
}

func (c *Controller) doStartClient(ctx context.Context, cfg *config.Config) {
	if !cfg.HasConnectTunnels() {
		return
	}

	connectTunnels := tunnelsByDirection(cfg, config.TunnelDirectionConnect)

	c.logger.Infof("Starting pig connect runtime | Tunnels: %d", len(connectTunnels))

	c.scriptExecutor = script.New(c.logger, cfg.ScriptPath)

	if c.needsSharedAdapter(connectTunnels) {
		adapterCfg := &cfg.Adapter
		if err := c.setupSharedClientAdapter(ctx, adapterCfg); err != nil {
			c.logger.Fatalf("Failed to setup adapter: %v", err)
		}
	}

	for _, tunnelCfg := range connectTunnels {
		if err := c.AddClientTunnel(ctx, tunnelCfg); err != nil {
			c.logger.Fatalf("Failed to add client tunnel: %v", err)
		}
	}
}

func (c *Controller) needsSharedAdapter(tunnelCfgs []*config.TunnelConfig) bool {
	if len(tunnelCfgs) == 0 {
		return false
	}
	if len(tunnelCfgs) == 1 {
		return tunnelCfgs[0].Adapter == nil
	}
	for _, tunnelCfg := range tunnelCfgs {
		if tunnelCfg.Adapter == nil {
			return true
		}
	}
	return false
}

// setupSharedClientAdapter creates the adapter and starts the reader goroutine that dispatches
// packets via the demux. Must be called after demux is initialized.
func (c *Controller) setupSharedClientAdapter(ctx context.Context, cfg *config.AdapterConfig) error {
	adapter, err := c.createAdapter(cfg, false)
	if err != nil {
		return err
	}
	c.sharedClientAdapter = adapter
	c.demux = demux.New(c.logger, c.sharedClientAdapter).WithBufferPool(c.bufferPool)
	c.demux.Start(ctx)
	c.logger.Infof("Created shared adapter %s, IP: %s, MTU %d", c.sharedClientAdapter.Name(), c.sharedClientAdapter.IP(), c.sharedClientAdapter.MTU())
	return nil
}

// AddClientTunnel creates and starts a client tunnel from the given config.
// It can be called after StartClient to attach additional tunnels at runtime
// (e.g. when a control plane pushes new peer configurations).
func (c *Controller) AddClientTunnel(ctx context.Context, tunnelCfg *config.TunnelConfig) error {
	if tunnelCfg.Direction != config.TunnelDirectionConnect {
		return fmt.Errorf("tunnel %s is not a connect tunnel", tunnelCfg.Name)
	}

	tunnelInfo, dialFunc, err := c.newClientTunnel(ctx, tunnelCfg)
	if err != nil {
		return err
	}

	c.tunnelsWg.Go(func() { c.runClientTunnel(ctx, tunnelInfo, dialFunc, tunnelCfg.ReconnectInterval) })

	return nil
}

func (c *Controller) newClientTunnel(ctx context.Context, tunnelCfg *config.TunnelConfig) (*TunnelInfo, func(ctx context.Context) (transport.Conn, error), error) {
	logger := c.logger.WithFields([]common.LoggerField{
		{Key: "tunnel", Value: tunnelCfg.Name},
	})

	transportStr := "New tunnel"
	if tunnelCfg.ICE == nil || !tunnelCfg.ICE.Enabled {
		transportStr += fmt.Sprintf(" | Transport:%s | Target: %s:%d", tunnelCfg.Proto, tunnelCfg.Connect.Address, tunnelCfg.Connect.Port)
	}
	logger.Infof(transportStr)

	authenticator, err := c.createClientAuthenticator(tunnelCfg.Auth)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create authenticator: %w", err)
	}

	var (
		adapterCfg = tunnelCfg.Adapter
		useAdapter common.TunnelAdapter
	)
	switch adapterCfg {
	case nil:
		if c.sharedClientAdapter == nil {
			return nil, nil, fmt.Errorf("adapter not initialized; call StartClient first")
		}
		if c.demux == nil {
			return nil, nil, fmt.Errorf("demux not initialized; call StartClient first")
		}
		adapterCfg = &c.cfg.Adapter
		useAdapter = c.demux.NewAdapter(ctx, 1024)
	default:
		tunAdapter, err := c.createAdapter(tunnelCfg.Adapter, false)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create adapter: %w", err)
		}
		useAdapter = tunAdapter
	}

	tunnel, err := client.NewWithAdapter(logger, adapterCfg, tunnelCfg, useAdapter, authenticator)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create client: %w", err)
	}
	tunnel = tunnel.WithBufferPool(c.bufferPool)

	tunnelInfo := &TunnelInfo{
		Logger: logger,
		Tunnel: tunnel,
	}

	dialFunc, err := c.getDialFunc(tunnelInfo, useAdapter.MTU())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create dialer: %w", err)
	}

	if err := c.StoreTunnelInfo(tunnelInfo); err != nil {
		return nil, nil, err
	}

	return tunnelInfo, dialFunc, nil
}

func (c *Controller) runClientTunnel(ctx context.Context, tunnelInfo *TunnelInfo, dialFunc func(ctx context.Context) (transport.Conn, error), reconnectInterval int) {
	t := time.NewTimer(0)
	defer t.Stop()

	tunnel := tunnelInfo.Tunnel.(*client.Client)
	logger := tunnelInfo.Logger

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	c.tunnelsWg.Go(func() { c.handleClientEvents(ctx, tunnelInfo) })
	for {
		select {
		case <-t.C:
		case <-ctx.Done():
			logger.Debug("Controller exiting, tunnel stopped")
			return
		}
		if err := tunnel.Start(ctx, dialFunc); err != nil {
			logger.Fatalf("Failed to start tunnel: %v", err)
		}
		tunnel.Wait()
		if common.IsContextDone(ctx) {
			logger.Debug("Controller exiting, tunnel stopped")
			return
		}
		if reconnectInterval <= 0 {
			return
		}
		logger.Infof("Retrying connection in %d seconds", reconnectInterval)
		t.Reset(time.Duration(reconnectInterval) * time.Second)
	}
}
