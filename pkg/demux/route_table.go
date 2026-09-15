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

package demux

import (
	"math/bits"
	"net"
	"slices"
	"sync"

	"github.com/riraccuia/pig/pkg/config"
)

type tunnelRoute struct {
	network *net.IPNet
	tunnel  *Adapter
}

type routeTable struct {
	mu            sync.RWMutex
	routes        []tunnelRoute
	defaultTunnel *Adapter
}

func newRouteTable() *routeTable {
	return &routeTable{}
}

func (rt *routeTable) addRoutes(ta *Adapter, routes []config.Route) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for _, r := range routes {
		_, ipNet, err := net.ParseCIDR(r.Destination)
		if err != nil {
			continue
		}
		rt.routes = append(rt.routes, tunnelRoute{network: ipNet, tunnel: ta})
	}
	slices.SortFunc(rt.routes, func(a, b tunnelRoute) int {
		return prefixLen(b.network.Mask) - prefixLen(a.network.Mask)
	})
}

func (rt *routeTable) removeRoutes(ta *Adapter) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.routes = slices.DeleteFunc(rt.routes, func(r tunnelRoute) bool {
		return r.tunnel == ta
	})
	if rt.defaultTunnel == ta {
		rt.defaultTunnel = nil
	}
}

func (rt *routeTable) setDefault(ta *Adapter) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.defaultTunnel = ta
}

func prefixLen(mask net.IPMask) int {
	n := 0
	for _, b := range mask {
		n += bits.OnesCount8(b)
	}
	return n
}

func (rt *routeTable) lookup(dst net.IP) *Adapter {
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for _, r := range rt.routes {
		if r.network.Contains(dst) {
			return r.tunnel
		}
	}
	return rt.defaultTunnel
}
