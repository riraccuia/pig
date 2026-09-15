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
	"runtime"

	"github.com/riraccuia/pig/pkg/client"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/demux"
)

// HandleClientEvents starts monitoring events for a client tunnel that was
// created externally (e.g. in tests). It has no associated TunnelConfig so
// only peer-bypass routes are managed.
func (c *Controller) HandleClientEvents(tunnel *client.Client) {
	c.Add(1)
	go c.handleClientEvents(c.ctx, tunnel)
	runtime.Gosched()
}

func (c *Controller) onTunnelConnected(tunnel *client.Client) error {
	ta, ok := tunnel.GetAdapter().(*demux.Adapter)
	if !ok {
		c.logger.Errorf("unexpected tunnel adapter type %T", tunnel.GetAdapter())
		return fmt.Errorf("unexpected tunnel adapter type %T", tunnel.GetAdapter())
	}
	tunnelCfg := tunnel.Config()
	if tunnelCfg == nil || len(tunnelCfg.Routes) == 0 {
		c.demux.SetDefault(ta)
		return nil
	}
	c.demux.AddRoutes(ta, tunnelCfg.Routes)
	var addRoutes []config.Route
	/*peerAddr := tunnel.PeerAddr()
	if peerAddr != nil {
		if pb, err := peerBypassRoute(peerAddr); err == nil {
			addRoutes = append(addRoutes, pb)
		}
	}*/
	addRoutes = append(addRoutes, tunnelCfg.Routes...)
	select {
	case c.routeRequests <- routeRequest{op: routeOpAdd, routes: addRoutes}:
	default:
		c.logger.Errorf("failed to send route add request: channel is full")
	}
	return nil
}

func (c *Controller) onTunnelDisconnected(tunnel *client.Client) error {
	ta, ok := tunnel.GetAdapter().(*demux.Adapter)
	if !ok {
		c.logger.Errorf("unexpected tunnel adapter type %T", tunnel.GetAdapter())
		return fmt.Errorf("unexpected tunnel adapter type %T", tunnel.GetAdapter())
	}
	c.demux.RemoveRoutes(ta)

	tunnelCfg := tunnel.Config()
	if tunnelCfg == nil || len(tunnelCfg.Routes) == 0 {
		return nil
	}
	removeRoutes := tunnelCfg.Routes
	if pb, err := peerBypassRoute(tunnel.LastPeerAddr()); err == nil {
		removeRoutes = append(removeRoutes, pb)
	}
	if len(removeRoutes) == 0 {
		return nil
	}
	c.routeRequests <- routeRequest{op: routeOpRemove, routes: removeRoutes}
	return nil
}

func (c *Controller) handleClientEventsAsync(ctx context.Context, tunnel *client.Client) {
	c.Add(1)
	go c.handleClientEvents(ctx, tunnel)
	runtime.Gosched()
}

func (c *Controller) handleClientEvents(ctx context.Context, tunnel *client.Client) {
	defer c.Done()
	// tunnelCfg is assumed never nil for controller-managed tunnels (AddClientTunnel path).
	// HandleClientEvents may pass nil for externally-created clients; route/demux ops are skipped in that case.

	for {
		var event *client.EventContext
		select {
		case event = <-tunnel.Events():
		case <-ctx.Done():
			tunnel.WaitClose()
			if len(tunnel.Events()) == 0 {
				c.logger.Debugf("Stopped monitoring client events")
				return
			}
			continue
		}

		c.logger.Debugf("Client event received: %s", event.State)

		tunnelCfg := tunnel.Config()

		switch event.State {
		case client.StateConnected:
			err := c.onTunnelConnected(tunnel)
			if err != nil {
				c.logger.Errorf("failed to handle tunnel connected event: %v", err)
				continue
			}
		case client.StateDisconnected, client.StateStopped:
			err := c.onTunnelDisconnected(tunnel)
			if err != nil {
				c.logger.Errorf("failed to handle tunnel disconnected event: %v", err)
				continue
			}
		}

		var proto config.TransportType
		if tunnelCfg != nil {
			proto = tunnelCfg.Proto
		}
		c.executeClientScript(proto, tunnel, event)
	}
}
