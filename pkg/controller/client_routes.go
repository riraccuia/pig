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
	"net"
	"runtime"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/route"
)

// routeOp identifies the type of route operation sent to the route manager goroutine.
type routeOp int

const (
	routeOpAdd routeOp = iota
	routeOpRemove
)

// routeRequest is sent to the central route manager goroutine. Add and remove
// operations are serialised; routes are pre-built by the caller.
type routeRequest struct {
	op     routeOp
	routes []config.Route
}

func (c *Controller) ManageRoutes() {
	c.Add(1)
	// Central route manager goroutine: installs global routes once, then
	// processes per-tunnel add/remove requests for the controller lifetime.
	go c.manageRoutes(c.ctx, c.cfg)
	runtime.Gosched()
}

// manageRoutes is the single goroutine that owns all route table mutations.
// It installs global routes (bypass/static from RouteConfig) once, then
// processes add/remove requests. Callers supply the routes to add or remove.
func (c *Controller) manageRoutes(ctx context.Context, cfg *config.Config) {
	defer c.Done()

	c.routeRequests = make(chan routeRequest, 16)

	routeCfg := &cfg.RouteConfig
	if !routeCfg.Enabled {
		// Routing disabled -- drain requests so senders never block.
		for {
			select {
			case <-ctx.Done():
				return
			case <-c.routeRequests:
			}
		}
	}

	c.logger.Infof("Route manager started")

	// Install global routes once (bypass + static from RouteConfig.Routes).
	c.installGlobalRoutes(routeCfg)

	for {
		select {
		case <-ctx.Done():
			c.logger.Infof("Route manager shutting down, cleaning up all routes")
			if err := c.routeManager.Cleanup(); err != nil {
				c.logger.Errorf("Failed to cleanup routes: %v", err)
			}
			return
		case req := <-c.routeRequests:
			switch req.op {
			case routeOpAdd:
				c.handleRouteAdd(req.routes)
			case routeOpRemove:
				c.handleRouteRemove(req.routes)
			}
		}
	}
}

// installGlobalRoutes adds the routes defined in the top-level RouteConfig.
// These persist for the lifetime of the controller and are not tied to any
// individual tunnel.
func (c *Controller) installGlobalRoutes(routeCfg *config.RouteConfig) {
	for _, r := range routeCfg.Routes {
		rt, err := c.buildRoute(r)
		if err != nil {
			c.logger.Errorf("Failed to build global route %s: %v", r.Destination, err)
			continue
		}
		if err := c.routeManager.AddRoute(rt); err != nil {
			c.logger.Errorf("Failed to add global route %s: %v", r.Destination, err)
		}
	}
}

// handleRouteAdd installs the given routes.
func (c *Controller) handleRouteAdd(routes []config.Route) {
	if len(routes) == 0 {
		return
	}
	c.logger.Infof("Adding %d route(s)", len(routes))
	for _, r := range routes {
		rt, err := c.buildRoute(r)
		if err != nil {
			c.logger.Errorf("Failed to build route %s: %v", r.Destination, err)
			continue
		}
		if r.Type == config.RouteTypeTunnel {
			c.logger.Infof("Routing %s to %s via %s", rt.Destination, rt.Gateway, rt.Interface)
		}
		if err := c.routeManager.AddRoute(rt); err != nil {
			c.logger.Errorf("Failed to add route %s: %v", r.Destination, err)
		}
	}
}

// handleRouteRemove tears down the given routes.
func (c *Controller) handleRouteRemove(routes []config.Route) {
	if len(routes) == 0 {
		return
	}
	c.logger.Infof("Removing %d route(s)", len(routes))
	for _, r := range routes {
		rt, err := c.buildRoute(r)
		if err != nil {
			c.logger.Errorf("Failed to build route for removal %s: %v", r.Destination, err)
			continue
		}
		if err := c.routeManager.RemoveRoute(rt); err != nil {
			c.logger.Errorf("Failed to remove route %s: %v", rt.String(), err)
		}
	}
}

func ipNetFromAddrString(addr string) (*net.IPNet, error) {
	_, ipNet, err := net.ParseCIDR(addr)
	if err == nil && ipNet != nil {
		return ipNet, nil
	}
	host := net.ParseIP(addr)
	if host == nil {
		return nil, err
	}
	maskBits := 32
	if host.To4() == nil {
		maskBits = 128
	}
	ipNet = &net.IPNet{IP: host, Mask: net.CIDRMask(maskBits, maskBits)}
	return ipNet, nil
}

// buildRoute converts a config.Route into a *route.Route ready for the
// route manager. For bypass routes it resolves the best gateway; for tunnel
// routes it uses the shared adapter's address.
func (c *Controller) buildRoute(r config.Route) (*route.Route, error) {
	ipNet, err := ipNetFromAddrString(r.Destination)
	if err != nil {
		return nil, fmt.Errorf("failed to convert destination %s to IPNet: %w", r.Destination, err)
	}

	switch r.Type {
	case config.RouteTypeBypass:
		best, err := c.routeManager.FindBestRoute(ipNet.IP)
		if err != nil {
			return nil, fmt.Errorf("find best route for %s: %w", ipNet, err)
		}
		if best.IsDirectlyConnected() {
			return best, nil //fmt.Errorf("%s is directly connected via %s (%s)", ipNet, best.LinkAddr, best.Interface)
		}
		/*if !best.HasGateway() {
			return nil, fmt.Errorf("no suitable gateway for %s", ipNet)
		}*/
		best.Destination = ipNet
		return best, nil

	case config.RouteTypeStatic:
		gw := net.ParseIP(r.Gateway)
		if gw == nil {
			return nil, fmt.Errorf("invalid gateway %q", r.Gateway)
		}
		logStr := fmt.Sprintf("Adding static route %s via %s", ipNet, gw)
		if r.Interface != "" {
			logStr += fmt.Sprintf(" on <%s>", r.Interface)
		}
		c.logger.Infof(logStr)
		return &route.Route{
			Destination: ipNet,
			Gateway:     gw,
			Interface:   r.Interface,
		}, nil

	case config.RouteTypeTunnel:
		dest := c.clientAdapter.IP()
		if ipNet.IP.To4() == nil {
			dest = c.clientAdapter.IP6()
		}
		if dest == nil {
			return nil, fmt.Errorf("no suitable tunnel address for %s", ipNet)
		}
		//c.logger.Infof("Routing %s to %s via %s", ipNet, dest, c.clientAdapter.Name())
		return &route.Route{
			Destination: ipNet,
			Gateway:     dest,
			Interface:   c.clientAdapter.Name(),
		}, nil

	default:
		return nil, fmt.Errorf("unknown route type %q", r.Type)
	}
}

// peerBypassRoute builds a bypass config.Route for the remote peer address
// so that traffic to the peer itself doesn't get routed into the tunnel.
func peerBypassRoute(addr net.Addr) (config.Route, error) {
	if addr == nil {
		return config.Route{}, fmt.Errorf("no address provided")
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil && addr.Network() == "ip" {
		host = addr.String()
		err = nil
	}
	if err != nil {
		return config.Route{}, fmt.Errorf("split host/port (%s): %w", addr.Network(), err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return config.Route{}, fmt.Errorf("parse IP %q", host)
	}
	bits := 32
	if ip.To4() == nil {
		bits = 128
	}
	return config.Route{
		Destination: fmt.Sprintf("%s/%d", ip, bits),
		Type:        config.RouteTypeBypass,
	}, nil
}
