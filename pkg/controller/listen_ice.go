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
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/transport"
	"github.com/riraccuia/pig/pkg/transport/dtls"
	qt "github.com/riraccuia/pig/pkg/transport/quic-go"
	trtls "github.com/riraccuia/pig/pkg/transport/tls"
	"github.com/riraccuia/pig/pkg/transport/tlsicmp"
	"github.com/riraccuia/pig/pkg/transport/ws"
)

func (c *Controller) getICEListenFunc(cfg *config.TunnelConfig) (func(ctx context.Context) (transport.Listener, error), error) {
	listenPort := uint16(cfg.Listen.Port)
	if listenPort == 0 {
		// use a random port
		listenPort = uint16(rand.Intn(65535-1024) + 1024)
	}
	c.logger.Infof("Starting ICE | Candidate protocols: %v | Listen port: %d", strings.Join(cfg.ICE.Protos, ", "), listenPort)
	return func(ctx context.Context) (transport.Listener, error) {
		offerPathsChan, err := ice.NewPathConnector(signaling.GetOptions(c.logger, cfg.ICE), cfg.ICE.UseProtos(), c.adapters).GetListenPaths(ctx, listenPort)
		if err != nil {
			return nil, fmt.Errorf("failed to get listen paths: %w", err)
		}
		tlsConfig, err := c.createTLSConfig(config.TunnelDirectionListen, cfg)
		if err != nil {
			c.logger.Errorf("failed to create TLS config: %v", err)
			return nil, err
		}
		iceListener := ice.NewListener(ctx, nil)
		go c.receiveICEServerConnectPaths(ctx, cfg, cfg.Adapter.BindAdapter, cfg.Adapter.MTU, tlsConfig, offerPathsChan, iceListener)
		return iceListener, nil
	}, nil
}

func (c *Controller) receiveICEServerConnectPaths(ctx context.Context, cfg *config.TunnelConfig, bindAdapter string, mtu int, tlsConfig *tls.Config, offerPathsChan <-chan *ice.OfferPaths, pigListener *ice.Listener) {
	for {
		select {
		case <-ctx.Done():
			c.logger.Errorf("Aborting listen paths processor: %v", ctx.Err())
			return
		case offerPaths := <-offerPathsChan:
			go c.processICEServerConnectPaths(ctx, cfg, bindAdapter, mtu, tlsConfig, offerPaths, pigListener)
		}
	}
}

func (c *Controller) processICEServerConnectPaths(ctx context.Context, cfg *config.TunnelConfig, bindAdapter string, mtu int, tlsConfig *tls.Config, offerPaths *ice.OfferPaths, pigListener *ice.Listener) {
	var (
		err          error
		nominatedPtr atomic.Pointer[ice.ConnectPath]
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

	wg := &sync.WaitGroup{}

	for _, cp := range offerPaths.ConnectPaths {
		path := cp
		wg.Go(func() {
			if c.connectICEListenPath(bindCtx, path, bindAdapter, &nominatedPtr) {
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

	c.logger.Infof("ICE candidate nominated: %s", selectedPath.String())

	var l transport.Listener
	switch selectedPath.Protocol.Protocol {
	case "quic":
		co := network.NewUDPPacketConn(selectedPath.Conn.(*net.UDPConn))
		l, err = qt.GetListenerFromConn(ctx, co, cfg, tlsConfig)
	case "ws":
		l, err = ws.GetListenerFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
	case "dtls":
		co := network.NewUDPPacketConn(selectedPath.Conn.(*net.UDPConn))
		l, err = dtls.GetListenerFromConn(ctx, co, cfg, tlsConfig, mtu)
	case "tls":
		l, err = trtls.GetListenerFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
	case "tls-in-icmp":
		l, err = tlsicmp.GetListenerFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
	}
	if err != nil {
		c.logger.Errorf("Failed to get listener for %s: %v", selectedPath.String(), err)
		return
	}
	c.logger.Infof("ICE completed | %s", selectedPath.String())
	pigListener.Load(l) //nolint:errcheck
}

func (c *Controller) connectICEListenPath(ctx context.Context, cp *ice.ConnectPath, bindAdapter string, nominatedPtr *atomic.Pointer[ice.ConnectPath]) (selected bool) {
	c.logger.Debugf("Connecting ICE path | %s", cp.String())
	_, e := cp.Connect(ctx)
	if e == ice.ErrConnectICMP {
		_, e = cp.ConnectICMP(ctx, c.logger, bindAdapter, true)
	}
	if errors.Is(e, context.Canceled) {
		return
	}
	if e != nil {
		c.logger.Tracef("Failed to connect ICE path %s: %v", cp.String(), e)
		return
	}
	//if cp.Protocol.Network != "icmp" {
	_, e = cp.BindAgent.Bind(ctx)
	//}
	if errors.Is(e, context.Canceled) {
		return
	}
	if e != nil {
		c.logger.Tracef("Failed to bind ICE path %s: %v", cp.String(), e)
		return
	}
	selected, e = cp.BindAgent.ICEWaitNominated(ctx)
	if e != nil || !selected {
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
