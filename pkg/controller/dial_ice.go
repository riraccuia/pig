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
	"net"
	"os"
	"strings"
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

		c.logger.Debugf("ICE connect path nominated: %s", selectedPath.String())

		_, err = selectedPath.BindAgent.ICENominateCandidate()
		selectedPath.BindAgent.StopReceive()
		if err != nil {
			return nil, fmt.Errorf("failed to nominate ICE candidate: %w", err)
		}

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

	for _, cp := range connectPaths {
		// attempt to connect all paths in parallel
		path := cp
		go c.connectICEDialPath(ctx, path, &selectedPtr)
	}

	lCtx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()

	var stop bool
	for !stop {
		select {
		case <-lCtx.Done():
			err = ctx.Err()
			stop = true
		default:
			// continue with the logic
		}
		selectedPath = selectedPtr.Load()
		if selectedPath != nil {
			break
		}
		time.Sleep(time.Millisecond * 10)
		//runtime.Gosched()
	}

	// close all connect paths that are not the selected path
	/*for _, cp := range connectPaths {
		if selectedPath == nil || cp != selectedPath {
			cp.CloseConn()
		}
	}*/

	if selectedPath == nil {
		err = errors.New("all ICE candidates failed")
		return
	}
	return
}

func (c *Controller) connectICEDialPath(ctx context.Context, cp *ice.ConnectPath, selectedPath *atomic.Pointer[ice.ConnectPath]) {
	var e error
	// bypass via the best route
	bypassRoute := config.Route{
		Destination: cp.RemoteIP.String(),
		Type:        config.RouteTypeBypass,
	}
	rt, err := c.buildRoute(bypassRoute)
	if err != nil {
		c.logger.Errorf("Failed to build bypass route for %s: %v", cp.RemoteIP.String(), err)
		return
	}

	viaStr := fmt.Sprintf("on <%s>", rt.Interface)
	if rt.Gateway != nil {
		viaStr += fmt.Sprintf(" via %s", rt.Gateway.String())
	}

	c.logger.Debugf("Bypassing %s %s", rt.Destination.String(), viaStr)

	var routeExists bool

	err = c.routeManager.AddRoute(rt)
	if os.IsExist(err) {
		err = nil
		routeExists = true
		c.logger.Debugf("Skipped bypass route for %s as it already exists", cp.RemoteIP.String())
	}
	if errors.Is(err, route.ErrDirectlyConnected) { //err != nil && strings.Contains(err.Error(), "directly connected") {
		c.logger.Debugf("Skipped bypass route: %v", err)
		err = nil
		routeExists = true
	}
	if err != nil {
		c.logger.Errorf("Failed to add bypass route for %s: %v", cp.RemoteIP.String(), err)
		return
	}

	if !routeExists {
		defer func() {
			if e == nil {
				return
			}
			//c.routeRequests <- routeRequest{op: routeOpRemove, routes: []config.Route{bypassRoute}}
			err = c.routeManager.RemoveRoute(rt)
			if err != nil {
				c.logger.Errorf("Failed to remove bypass route for %s: %v", cp.RemoteIP.String(), err)
			}
		}()
	}

	c.logger.Debugf("Connecting ICE path | %s", cp.String())
	_, e = cp.Connect()
	if e == ice.ErrConnectICMP {
		_, e = cp.ConnectICMP(ctx, c.logger, c.cfg.Adapter.BindAdapter, false)
	}
	if e != nil {
		c.logger.Tracef("Failed to connect ICE path %s: %v", cp.String(), e)
		return
	}
	e = cp.ICESetup()
	if e != nil {
		cp.CloseConn()
		//c.logger.Tracef("Failed to ICE bind path %s: %v", cp.String(), e)
		return
	}
	// if the selected path is not set, set it to the current path
	if !selectedPath.CompareAndSwap(nil, cp) {
		// if the selected path is already set, close the current path
		cp.CloseConn()
		e = errors.New("selected path already set")
	}
}
