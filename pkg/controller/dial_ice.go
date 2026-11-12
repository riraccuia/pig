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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/route"
	"github.com/riraccuia/pig/pkg/transport"
	"github.com/riraccuia/pig/pkg/transport/dtls"
	icmp "github.com/riraccuia/pig/pkg/transport/icmp"
	qt "github.com/riraccuia/pig/pkg/transport/quic-go"
	trtls "github.com/riraccuia/pig/pkg/transport/tls"
	"github.com/riraccuia/pig/pkg/transport/tlsicmp"
	"github.com/riraccuia/pig/pkg/transport/wireguard"
	"github.com/riraccuia/pig/pkg/transport/ws"
)

func (c *Controller) getICEDialFunc(tunnelInfo *TunnelInfo, mtu int) (func(ctx context.Context) (transport.Conn, error), error) {
	cfg := tunnelInfo.Tunnel.Config()
	logger := tunnelInfo.Logger

	tlsConfig, err := c.createTLSConfig(config.TunnelDirectionConnect, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}
	signalingOpts := signaling.GetOptions(logger, cfg.ICE)
	signalingOpts.Dialer = c.bypassDialer

	pc, err := ice.NewPathFinder(signalingOpts, cfg.ICE.UseProtos())
	if err != nil {
		return nil, fmt.Errorf("failed to create path connector: %w", err)
	}

	return func(ctx context.Context) (transport.Conn, error) {
		logger.Infof("Starting ICE | Candidate protocols: %v", strings.Join(cfg.ICE.Protos, ", "))
		connectPaths, scheduledAt, err := pc.GetConnectPaths(ctx, cfg.Connect, &c.adapters)
		if err != nil {
			return nil, fmt.Errorf("failed to get ICE connect paths: %w", err)
		}
		if len(connectPaths) == 0 {
			return nil, fmt.Errorf("no ICE candidates found")
		}

		selectedPath, err := c.processICEClientConnectPaths(ctx, tunnelInfo, connectPaths, scheduledAt)
		if err != nil || selectedPath == nil {
			return nil, fmt.Errorf("failed to process ICE client connect paths: %w", err)
		}

		_, err = selectedPath.BindAgent.ICENominateCandidate(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to nominate ICE candidate: %w", err)
		}

		logger.Debugf("ICE candidate nominated: %s", selectedPath.String())

		selectedPath.BindAgent.StopReceive()

		logger.Infof("ICE completed | %s", selectedPath.String())

		// Allow the server to set up the listening side of the connection
		time.Sleep(time.Millisecond * 100)

		switch selectedPath.Protocol.Protocol {
		case string(config.TransportWS):
			return ws.GetClientFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
		case string(config.TransportQUIC):
			return qt.GetClientFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
		case string(config.TransportDTLS):
			return dtls.GetClientFromConn(ctx, selectedPath.Conn, cfg, tlsConfig, mtu)
		case string(config.TransportTLS):
			return trtls.GetClientFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
		case string(config.TransportWG):
			return wireguard.GetClientFromConn(ctx, selectedPath.Conn, cfg, mtu)
		case string(config.TransportTLSICMP):
			return tlsicmp.GetClientFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
		}
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
	}, nil
}

func (c *Controller) processICEClientConnectPaths(ctx context.Context, tunnelInfo *TunnelInfo, connectPaths []*ice.ConnectPath, scheduledAt time.Time) (selectedPath *ice.ConnectPath, err error) {
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

	wg := sync.WaitGroup{}
	ctx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()

	// build the bypass routes for the remote IPs
	bypassRoutes := map[string]*route.Route{}
	for _, cp := range connectPaths {
		if _, ok := bypassRoutes[cp.RemoteIP.String()]; ok {
			continue
		}
		bypassRoutes[cp.RemoteIP.String()] = c.bypassTarget(tunnelInfo.Logger, cp.RemoteIP)
	}

	for _, cp := range connectPaths {
		// attempt to connect all paths in parallel
		path := cp
		wg.Go(func() {
			if c.connectICEDialPath(ctx, tunnelInfo, path, &selectedPtr) {
				// we have a winner, cancel everything else
				cancel()
			}
		})
	}

	wg.Wait()

	selectedPath = selectedPtr.Load()

	switch selectedPath {
	case nil:
		err = errors.New("all ICE candidates failed")
	default:
		// set the route from the selected path as tunnel active route
		activeBypassRoute := bypassRoutes[selectedPath.RemoteIP.String()]
		tunnelInfo.NewActiveRoute(activeBypassRoute)
		delete(bypassRoutes, selectedPath.RemoteIP.String())
	}

	// cleanup unused bypass routes
	for _, rt := range bypassRoutes {
		if rt == nil {
			continue
		}
		c.RouteRemove(tunnelInfo.Logger, rt, nil)
	}

	return
}

func (c *Controller) connectICEDialPath(ctx context.Context, tunnelInfo *TunnelInfo, cp *ice.ConnectPath, selectedPath *atomic.Pointer[ice.ConnectPath]) (selected bool) {
	logger := tunnelInfo.Logger

	logger.Debugf("Connecting ICE path | %s", cp.String())
	var err error
	switch cp.Protocol.Network {
	case "icmp":
		cfg := tunnelInfo.Tunnel.Config()
		bindAdapter := ""
		if cfg.Adapter == nil || cfg.Adapter.BindAdapter == "" {
			logger.Error("bind adapter not configured for icmp based paths")
			return
		}
		bindAdapter = cfg.Adapter.BindAdapter
		err = icmp.SetupGlobalListenerOnce(context.Background(), c.logger, bindAdapter, false)
		if err != nil {
			logger.Errorf("failed to setup icmp listener: %w", err)
			return
		}
		_, err = cp.ConnectICMP(ctx, logger, bindAdapter, false)
	default:
		_, err = cp.Connect(ctx)
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	if err != nil {
		logger.Tracef("Failed to connect ICE path %s: %v", cp.String(), err)
		return
	}
	_, err = cp.BindAgent.Bind(ctx)
	if errors.Is(err, context.Canceled) {
		cp.CloseConn()
		return
	}
	if err != nil {
		logger.Tracef("Failed to bind ICE path %s: %v", cp.String(), err)
		cp.CloseConn()
		return
	}
	// if the selected path is not set, set it to the current path
	if !selectedPath.CompareAndSwap(nil, cp) {
		// if the selected path is already set, close the current path
		cp.CloseConn()
		return
	}
	logger.Tracef("Bound ICE path %s", cp.String())
	selected = true
	return
}
