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
	"net"

	"github.com/riraccuia/pig/pkg/client"
	"github.com/riraccuia/pig/pkg/config"
)

// TunnelState holds a tunnel's config and current connection state.
type TunnelState struct {
	Name      string
	TunnelCfg *config.TunnelConfig
	State     client.State
	PeerAddr  net.Addr
}

// RouteState holds whether a network is reachable via a connected tunnel.
type RouteState struct {
	Network   string
	Connected bool
	TunnelCfg *config.TunnelConfig
}

// TunnelStates returns a snapshot of all added tunnels with their state.
func (c *Controller) TunnelStates() []TunnelState {
	var out []TunnelState
	c.tunnels.Range(func(key, value interface{}) bool {
		name := key.(string)
		tunnel := value.(*client.Client)
		tunnelCfg := tunnel.Config()
		out = append(out, TunnelState{
			Name:      name,
			TunnelCfg: tunnelCfg,
			State:     tunnel.State(),
			PeerAddr:  tunnel.PeerAddr(),
		})
		return true
	})
	return out
}

// RouteStates derives per-route reachability from tunnel states. Only tunnels
// with explicit routes are included; default tunnels are excluded.
func (c *Controller) RouteStates() []RouteState {
	var out []RouteState
	c.tunnels.Range(func(_, value interface{}) bool {
		tunnel := value.(*client.Client)
		tunnelCfg := tunnel.Config()
		if tunnelCfg == nil || len(tunnelCfg.Routes) == 0 {
			return true
		}
		connected := tunnel.State() == client.StateConnected
		for _, r := range tunnelCfg.Routes {
			if _, _, err := net.ParseCIDR(r.Destination); err != nil {
				continue
			}
			out = append(out, RouteState{
				Network:   r.Destination,
				Connected: connected,
				TunnelCfg: tunnelCfg,
			})
		}
		return true
	})
	return out
}
