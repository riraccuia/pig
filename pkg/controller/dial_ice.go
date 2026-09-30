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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/route"
	"github.com/riraccuia/pig/pkg/transport"
	"github.com/riraccuia/pig/pkg/transport/dtls"
	qt "github.com/riraccuia/pig/pkg/transport/quic-go"
	trtls "github.com/riraccuia/pig/pkg/transport/tls"
	"github.com/riraccuia/pig/pkg/transport/tlsicmp"
	"github.com/riraccuia/pig/pkg/transport/ws"
)

func (c *Controller) getICEDialFunc(cfg *config.TunnelConfig) (func(ctx context.Context) (transport.Conn, error), error) {
	tlsConfig, err := c.createTLSConfig(config.TunnelDirectionConnect, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}
	pc := ice.NewPathConnector(signaling.GetOptions(c.logger, cfg.ICE), cfg.ICE.UseProtos(), c.adapters)
	return func(ctx context.Context) (transport.Conn, error) {
		c.logger.Infof("Starting ICE | Candidate protocols: %v", strings.Join(cfg.ICE.Protos, ", "))
		connectPaths, scheduledAt, err := pc.GetConnectPaths(ctx, &cfg.Connect)
		if err != nil {
			return nil, fmt.Errorf("failed to get ICE connect paths: %w", err)
		}
		if len(connectPaths) == 0 {
			return nil, fmt.Errorf("no ICE candidates found")
		}

		selectedPath, err := c.processICEClientConnectPaths(ctx, connectPaths, scheduledAt)
		if err != nil || selectedPath == nil {
			return nil, fmt.Errorf("failed to process ICE client connect paths: %w", err)
		}

		_, err = selectedPath.BindAgent.ICENominateCandidate(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to nominate ICE candidate: %w", err)
		}

		c.logger.Debugf("ICE candidate nominated: %s", selectedPath.String())

		selectedPath.BindAgent.StopReceive()

		c.logger.Infof("ICE completed | %s", selectedPath.String())

		// Allow the server to set up the listening side of the connection
		time.Sleep(time.Millisecond * 100)

		switch selectedPath.Protocol.Protocol {
		case "ws":
			return ws.GetClientFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
		case "quic":
			co := network.NewUDPPacketConn(selectedPath.Conn.(*net.UDPConn))
			return qt.GetClientFromConn(ctx, co, cfg, tlsConfig)
		case "dtls":
			co := network.NewUDPPacketConn(selectedPath.Conn.(*net.UDPConn))
			co.SetReadBuffer(1024 * 2048)
			co.SetWriteBuffer(1024 * 2048)
			return dtls.GetClientFromConn(ctx, co, cfg, tlsConfig, c.cfg.Adapter.MTU)
		case "tls":
			return trtls.GetClientFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
		case "tls-in-icmp":
			return tlsicmp.GetClientFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
		}
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
	}, nil
}

func (c *Controller) processICEClientConnectPaths(ctx context.Context, connectPaths []*ice.ConnectPath, scheduledAt time.Time) (selectedPath *ice.ConnectPath, err error) {
	// wait for the scheduled time
	waitScheduled := time.After(time.Until(scheduledAt))
	select {
	case <-ctx.Done():
		err = ctx.Err()
		return
	case <-waitScheduled:
		break
	}

	selectedPtr := atomic.Pointer[ice.ConnectPath]{}

	wg := &sync.WaitGroup{}
	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	// build the bypass routes for the remote IPs
	remoteIPs := map[string]*route.Route{}
	for _, cp := range connectPaths {
		if _, ok := remoteIPs[cp.RemoteIP.String()]; ok {
			continue
		}
		rt, _ := c.bypassTarget(cp.RemoteIP)
		remoteIPs[cp.RemoteIP.String()] = rt
	}

	for _, cp := range connectPaths {
		// attempt to connect all paths in parallel
		path := cp
		wg.Go(func() {
			if c.connectICEDialPath(ctx, path, &selectedPtr) {
				// we have a winner, cancel everything else
				cancel()
			}
		})
	}

	wg.Wait()

	selectedPath = selectedPtr.Load()

	keepRoute := ""
	switch selectedPath {
	case nil:
		err = errors.New("all ICE candidates failed")
	default:
		keepRoute = selectedPath.RemoteIP.String()
	}

	for target, rt := range remoteIPs {
		if keepRoute == target {
			continue
		}
		e := c.routeManager.RemoveRoute(rt)
		if e != nil {
			c.logger.Errorf("Failed to remove bypass route for %s: %v", rt.Destination.String(), e)
		}
	}

	return
}

func (c *Controller) connectICEDialPath(ctx context.Context, cp *ice.ConnectPath, selectedPath *atomic.Pointer[ice.ConnectPath]) (selected bool) {
	c.logger.Debugf("Connecting ICE path | %s", cp.String())
	_, err := cp.Connect(ctx)
	if err == ice.ErrConnectICMP {
		_, err = cp.ConnectICMP(ctx, c.logger, c.cfg.Adapter.BindAdapter, false)
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	if err != nil {
		c.logger.Tracef("Failed to connect ICE path %s: %v", cp.String(), err)
		return
	}
	_, err = cp.BindAgent.Bind(ctx)
	if errors.Is(err, context.Canceled) {
		cp.CloseConn()
		return
	}
	if err != nil {
		c.logger.Tracef("Failed to bind ICE path %s: %v", cp.String(), err)
		cp.CloseConn()
		return
	}
	// if the selected path is not set, set it to the current path
	if !selectedPath.CompareAndSwap(nil, cp) {
		// if the selected path is already set, close the current path
		cp.CloseConn()
		return
	}
	c.logger.Tracef("Bound ICE path %s", cp.String())
	selected = true
	return
}

func (c *Controller) bypassTarget(target net.IP) (rt *route.Route, err error) {
	// bypass via the best route
	bypassRoute := config.Route{
		Destination: target.String(),
		Type:        config.RouteTypeBypass,
	}
	rt, err = c.buildRoute(bypassRoute)
	if err != nil {
		c.logger.Errorf("Failed to build bypass route for %s: %v", target.String(), err)
		return
	}

	viaStr := fmt.Sprintf("on <%s>", rt.Interface)
	if rt.Gateway != nil {
		viaStr += fmt.Sprintf(" via %s", rt.Gateway.String())
	}

	c.logger.Debugf("Bypassing %s %s", rt.Destination.String(), viaStr)

	err = c.routeManager.AddRoute(rt)
	if errors.Is(err, fs.ErrExist) {
		err = nil
		c.logger.Debugf("Skipped bypass route for %s as it already exists", target.String())
	}
	if errors.Is(err, route.ErrDirectlyConnected) {
		c.logger.Debugf("Skipped bypass route: %v", err)
		err = nil
	}
	if err != nil {
		c.logger.Errorf("Failed to add bypass route for %s: %v", target.String(), err)
		return
	}
	return
}
