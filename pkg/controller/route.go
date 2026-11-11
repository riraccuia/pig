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
	"errors"
	"fmt"
	"io/fs"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/demux"
	"github.com/riraccuia/pig/pkg/route"
)

func (c *Controller) setupRouteManager(ctx context.Context) {
	var err error
	c.routeManager, err = route.NewManager(ctx)
	if err != nil {
		c.logger.Fatalf("Failed to create route manager: %v", err)
	}
	c.bypassDialer = c.newBypassDialer(c.logger, time.Second*5)
	c.installGlobalRoutes(&c.cfg.RouteConfig)
}

// installGlobalRoutes adds the routes defined in the top-level RouteConfig.
// These persist for the lifetime of the controller and are not tied to any
// individual tunnel.
func (c *Controller) installGlobalRoutes(routeCfg *config.RouteConfig) {
	for _, r := range routeCfg.Routes {
		rt, err := c.buildRoute(r, c.sharedClientAdapter)
		if err != nil {
			c.logger.Errorf("Failed to build global route %s: %v", r.Destination, err)
			continue
		}
		c.logger.Infof("Adding global route | %s", rt.String())
		if _, err := c.routeManager.AddRoute(rt); err != nil {
			c.logger.Errorf("Failed to add global route %s: %v", r.Destination, err)
		}
	}
}

func (c *Controller) bypassTarget(logger common.Logger, target net.IP) (rt *route.Route) {
	if logger == nil {
		logger = c.logger
	}
	bypassRoute := config.Route{
		Destination: target.String(),
		Type:        config.RouteTypeBypass,
	}
	return c.RouteAdd(logger, bypassRoute, nil)
}

// RouteAddBulk installs the given routes.
func (c *Controller) RouteAddBulk(logger common.Logger, wantRoutes []config.Route, tunnelAdapter common.TunnelAdapter) (routes []*route.Route) {
	if !c.cfg.RouteConfig.Enabled || len(wantRoutes) == 0 {
		return nil
	}
	for _, r := range wantRoutes {
		rt := c.RouteAdd(logger, r, tunnelAdapter)
		if rt != nil {
			routes = append(routes, rt)
		}
	}
	return
}

// RouteRemove removes the given routes.
func (c *Controller) RouteRemoveBulk(logger common.Logger, routes []*route.Route, tunnelAdapter common.TunnelAdapter) {
	if !c.cfg.RouteConfig.Enabled || len(routes) == 0 {
		return
	}
	for _, r := range routes {
		c.RouteRemove(logger, r, tunnelAdapter)
	}
}

// RouteAdd installs the given route from the config.Route.
func (c *Controller) RouteAdd(logger common.Logger, wantRoute config.Route, tunnelAdapter common.TunnelAdapter) (rt *route.Route) {
	if !c.cfg.RouteConfig.Enabled {
		return nil
	}
	if logger == nil {
		logger = c.logger
	}
	rr, err := c.buildRoute(wantRoute, tunnelAdapter)
	if err != nil {
		logger.Errorf("Failed to build route %s: %v", wantRoute.Destination, err)
		return nil
	}
	switch wantRoute.Type {
	case config.RouteTypeTunnel:
		logger.Infof("Routing %s to %s via %s", rr.Destination, rr.Gateway, rr.Interface)
	case config.RouteTypeBypass:
		logger.Infof("Bypassing %s", rr.Destination)
	case config.RouteTypeStatic:
		gateway := rr.Gateway.String()
		if gateway == "" {
			gateway = "auto"
		}
		logger.Infof("Adding static route %s via interface <%s>, gateway <%s>", rr.Destination, rr.Interface, gateway)
	}
	rt, err = c.routeManager.AddRoute(rr)
	if errors.Is(err, fs.ErrExist) {
		err = nil
		logger.Debugf("Skipped %s route for %s as it already exists", wantRoute.Type, wantRoute.Destination)
	}
	if errors.Is(err, route.ErrDirectlyConnected) {
		logger.Debugf("Skipped %s route: %v", wantRoute.Type, err)
		err = nil
	}
	if err != nil {
		logger.Errorf("Failed to add %s route for %s: %v", wantRoute.Type, wantRoute.Destination, err)
	}
	return rt
}

// handleRouteRemove tears down the given routes.
func (c *Controller) RouteRemove(logger common.Logger, rt *route.Route, tunnelAdapter common.TunnelAdapter) bool {
	if !c.cfg.RouteConfig.Enabled {
		return false
	}
	if logger == nil {
		logger = c.logger
	}
	logger.Debugf("Removing route for %s", rt.Destination)
	err := c.routeManager.RemoveRoute(rt)
	if err != nil {
		logger.Errorf("Failed to remove route %s: %v", rt.String(), err)
	}
	return err == nil
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
func (c *Controller) buildRoute(r config.Route, tunnelAdapter common.TunnelAdapter) (*route.Route, error) {
	ipNet, err := ipNetFromAddrString(r.Destination)
	if err != nil {
		return nil, fmt.Errorf("failed to convert destination %s to IPNet: %w", r.Destination, err)
	}

	switch r.Type {
	case config.RouteTypeBypass:
		/*best, err := c.routeManager.FindBestRoute(ipNet.IP)
		if err != nil {
			return nil, fmt.Errorf("find best route for %s: %w", ipNet, err)
		}
		if best.IsDirectlyConnected() {
			return best, nil //fmt.Errorf("%s is directly connected via %s (%s)", ipNet, best.LinkAddr, best.Interface)
		}*
		/*if !best.HasGateway() {
			return nil, fmt.Errorf("no suitable gateway for %s", ipNet)
		}*/
		best := &route.Route{}
		best.Destination = ipNet
		return best, nil

	case config.RouteTypeStatic:
		gw := net.ParseIP(r.Gateway)
		if gw == nil {
			return nil, fmt.Errorf("invalid gateway %q", r.Gateway)
		}
		return &route.Route{
			Destination: ipNet,
			Gateway:     gw,
			Interface:   r.Interface,
		}, nil

	case config.RouteTypeTunnel:
		if tunnelAdapter == nil {
			return nil, fmt.Errorf("no tunnel adapter")
		}
		dest := tunnelAdapter.IP()
		if ipNet.IP.To4() == nil {
			dest = tunnelAdapter.IP6()
		}
		if dest == nil {
			return nil, fmt.Errorf("no suitable tunnel address for %s", ipNet)
		}
		//c.logger.Infof("Routing %s to %s via %s", ipNet, dest, c.clientAdapter.Name())
		return &route.Route{
			Destination: ipNet,
			Gateway:     dest,
			Interface:   tunnelAdapter.Name(),
		}, nil

	default:
		return nil, fmt.Errorf("unknown route type %q", r.Type)
	}
}

func (c *Controller) setupTunnelDemux(demuxAdapter *demux.Adapter, routes []config.Route) {
	var tunnelDest []string
	for _, r := range routes {
		if r.Type != config.RouteTypeTunnel {
			continue
		}
		tunnelDest = append(tunnelDest, r.Destination)
	}
	if len(tunnelDest) > 0 {
		c.demux.AddRoutes(demuxAdapter, tunnelDest)
	}
}

func (c *Controller) cleanupTunnelDemux(demuxAdapter *demux.Adapter) {
	c.demux.RemoveRoutes(demuxAdapter)
}
