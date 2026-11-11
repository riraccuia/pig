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

	"github.com/riraccuia/pig/pkg/client"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/demux"
	"github.com/riraccuia/pig/pkg/route"
)

func (c *Controller) onTunnelConnected(tunnelInfo *TunnelInfo) error {
	tunnel := tunnelInfo.Tunnel
	tunnelAdapter := tunnel.GetAdapter()
	tunnelCfg := tunnel.Config()
	switch ta := tunnelAdapter.(type) {
	case *demux.Adapter:
		c.setupTunnelDemux(ta, tunnelCfg.Routes)
	case common.TunnelAdapter:
	default:
		return fmt.Errorf("unexpected tunnel adapter type %T", tunnel.GetAdapter())
	}
	var addRoutes []config.Route
	addRoutes = append(addRoutes, tunnelCfg.Routes...)
	activeRoutes := c.RouteAddBulk(tunnelInfo.Logger, addRoutes, tunnelAdapter)
	for _, activeRoute := range activeRoutes {
		tunnelInfo.NewActiveRoute(activeRoute)
	}
	return nil
}

func (c *Controller) onTunnelDisconnected(tunnelInfo *TunnelInfo) error {
	tunnel := tunnelInfo.Tunnel
	tunnelAdapter := tunnel.GetAdapter()
	if demuxAdapter, ok := tunnelAdapter.(*demux.Adapter); ok {
		c.cleanupTunnelDemux(demuxAdapter)
	}

	activeRoutes := make([]*route.Route, 0)
	tunnelInfo.ActiveRoutes.Range(func(key, value any) bool {
		activeRoutes = append(activeRoutes, value.(*route.Route))
		return true
	})

	for _, activeRoute := range activeRoutes {
		if c.RouteRemove(tunnelInfo.Logger, activeRoute, tunnelAdapter) {
			tunnelInfo.DeleteActiveRoute(activeRoute)
		}
	}

	return nil
}

func (c *Controller) handleClientEvents(ctx context.Context, tunnelInfo *TunnelInfo) {
	// tunnelCfg is assumed never nil for controller-managed tunnels (AddClientTunnel path).
	// HandleClientEvents may pass nil for externally-created clients; route/demux ops are skipped in that case.

	tunnel := tunnelInfo.Tunnel.(*client.Client)
	logger := tunnelInfo.Logger

	for {
		var event *client.EventContext
		select {
		case event = <-tunnel.Events():
		case <-ctx.Done():
			tunnel.Wait()
			if len(tunnel.Events()) == 0 {
				logger.Debugf("Stopped monitoring client events")
				return
			}
			continue
		}

		c.logger.Debugf("Client event received: %s", event.State)

		switch event.State {
		case client.StateConnected:
			err := c.onTunnelConnected(tunnelInfo)
			if err != nil {
				logger.Errorf("failed to handle tunnel connected event: %v", err)
				continue
			}
		case client.StateDisconnected, client.StateStopped:
			err := c.onTunnelDisconnected(tunnelInfo)
			if err != nil {
				logger.Errorf("failed to handle tunnel disconnected event: %v", err)
				continue
			}
		}

		c.executeClientScript(tunnel, event)
	}
}
