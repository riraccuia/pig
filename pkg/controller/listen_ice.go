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
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/transport"
	"github.com/riraccuia/pig/pkg/transport/dtls"
	qt "github.com/riraccuia/pig/pkg/transport/quic-go"
	trtls "github.com/riraccuia/pig/pkg/transport/tls"
	"github.com/riraccuia/pig/pkg/transport/tlsicmp"
	"github.com/riraccuia/pig/pkg/transport/wireguard"
	"github.com/riraccuia/pig/pkg/transport/ws"
)

func (c *Controller) getICEListenFunc(tunnelInfo *TunnelInfo, mtu int) (func(ctx context.Context) (transport.Listener, error), error) {
	cfg := tunnelInfo.Tunnel.Config()
	logger := tunnelInfo.Logger

	listenPort := uint16(cfg.Listen.Port)
	if listenPort == 0 {
		// use a random port
		listenPort = uint16(rand.Intn(65535-1024) + 1024)
	}

	sigOpts := signaling.GetOptions(logger, cfg.ICE)
	sigOpts.Dialer = c.bypassDialer

	pc, err := ice.NewPathFinder(sigOpts, cfg.ICE.UseProtos())
	if err != nil {
		return nil, fmt.Errorf("failed to create path connector: %w", err)
	}
	return func(ctx context.Context) (transport.Listener, error) {
		logger.Infof("Starting ICE | Accepted protocols: %v | Listen port: %d", strings.Join(cfg.ICE.Protos, ", "), listenPort)
		offerPathsChan, err := pc.GetListenPaths(ctx, listenPort, &c.adapters)
		if err != nil {
			return nil, fmt.Errorf("failed to get listen paths: %w", err)
		}
		tlsConfig, err := c.createTLSConfig(config.TunnelDirectionListen, cfg)
		if err != nil {
			c.logger.Errorf("failed to create TLS config: %v", err)
			return nil, err
		}
		iceListener := ice.NewListener(ctx, nil)
		go c.receiveICEServerConnectPaths(ctx, tunnelInfo, mtu, tlsConfig, offerPathsChan, iceListener)
		return iceListener, nil
	}, nil
}

func (c *Controller) receiveICEServerConnectPaths(ctx context.Context, tunnelInfo *TunnelInfo, mtu int, tlsConfig *tls.Config, offerPathsChan <-chan *ice.OfferPaths, pigListener *ice.Listener) {
	for {
		select {
		case <-ctx.Done():
			c.logger.Errorf("Aborting listen paths processor: %v", ctx.Err())
			return
		case offerPaths := <-offerPathsChan:
			go c.processICEServerConnectPaths(ctx, tunnelInfo, mtu, tlsConfig, offerPaths, pigListener)
		}
	}
}

func (c *Controller) processICEServerConnectPaths(ctx context.Context, tunnelInfo *TunnelInfo, mtu int, tlsConfig *tls.Config, offerPaths *ice.OfferPaths, pigListener *ice.Listener) {
	var (
		cfg          = tunnelInfo.Tunnel.Config()
		nominatedPtr atomic.Pointer[ice.ConnectPath]
		err          error
		logger       = tunnelInfo.Logger
	)
	// wait for the scheduled time
	waitScheduled := time.After(time.Until(offerPaths.ScheduledAt))
	select {
	case <-ctx.Done():
		return
	case <-waitScheduled:
		break
	}

	bindCtx, bindCancel := context.WithTimeout(ctx, time.Second*5)
	defer bindCancel()

	wg := sync.WaitGroup{}

	for _, cp := range offerPaths.ConnectPaths {
		path := cp
		wg.Go(func() {
			if c.connectICEListenPath(bindCtx, tunnelInfo, path, &nominatedPtr) {
				// the controlling side nominated the path, cancel the context
				bindCancel()
			}
		})
	}

	wg.Wait()

	selectedPath := nominatedPtr.Load()

	if selectedPath == nil {
		return
	}

	logger.Infof("ICE candidate nominated: %s", selectedPath.String())

	var l transport.Listener
	switch selectedPath.Protocol.Protocol {
	case string(config.TransportQUIC):
		l, err = qt.GetListenerFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
	case string(config.TransportWS):
		l, err = ws.GetListenerFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
	case string(config.TransportDTLS):
		l, err = dtls.GetListenerFromConn(ctx, selectedPath.Conn, cfg, tlsConfig, mtu)
	case string(config.TransportTLS):
		l, err = trtls.GetListenerFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
	case string(config.TransportWG):
		l, err = wireguard.GetListenerFromConn(ctx, selectedPath.Conn, cfg, mtu)
	case string(config.TransportTLSICMP):
		l, err = tlsicmp.GetListenerFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
	}
	if err != nil {
		logger.Errorf("Failed to get listener for %s: %v", selectedPath.String(), err)
		return
	}
	logger.Infof("ICE completed | %s", selectedPath.String())
	pigListener.Load(l) //nolint:errcheck
}

func (c *Controller) connectICEListenPath(ctx context.Context, tunnelInfo *TunnelInfo, cp *ice.ConnectPath, nominatedPtr *atomic.Pointer[ice.ConnectPath]) (selected bool) {
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
		_, err = cp.ConnectICMP(ctx, logger, bindAdapter, true)
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
	//if cp.Protocol.Network != "icmp" {
	_, err = cp.BindAgent.Bind(ctx)
	//}
	if errors.Is(err, context.Canceled) {
		return
	}
	if err != nil {
		logger.Tracef("Failed to bind ICE path %s: %v", cp.String(), err)
		return
	}
	selected, err = cp.BindAgent.ICEWaitNominated(ctx)
	if err != nil || !selected {
		cp.CloseConn()
		return false
	}
	if !nominatedPtr.CompareAndSwap(nil, cp) {
		cp.CloseConn()
		return false
	}
	cp.BindAgent.StopReceive()
	return true
}
