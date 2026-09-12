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
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
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
		err            error
		connectedPaths = &sync.Map{}
		timer          = time.NewTimer(time.Second * 10)
		nomination     *ice.ConnectPath
	)
	// wait for the scheduled time
	waitScheduled := time.After(time.Until(offerPaths.ScheduledAt))
	select {
	case <-ctx.Done():
		return
	case <-waitScheduled:
		break
	}

	for _, cp := range offerPaths.ConnectPaths {
		path := cp
		go c.connectICEListenPath(ctx, path, bindAdapter, connectedPaths)
	}
	var stop bool
	for !stop {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			stop = true
		case <-timer.C:
			stop = true
		default:
			// continue with the logic
		}
		connectedPaths.Range(func(key, value any) bool {
			cp := value.(*ice.ConnectPath)
			if cp.BindAgent.ICENominated() {
				cp.BindAgent.StopReceive()
				nomination = cp
				return false
			}
			return true
		})
		if nomination != nil {
			break
		}
		time.Sleep(time.Millisecond * 10)
		//runtime.Gosched()
	}
	connectedPaths.Range(func(key, value any) bool {
		cp := value.(*ice.ConnectPath)
		if nomination == nil || cp != nomination {
			go cp.CloseConn()
		}
		return true
	})
	if nomination == nil {
		return
	}

	c.logger.Infof("ICE candidate nominated: %s", nomination.String())

	var l transport.Listener
	switch nomination.Protocol.Protocol {
	case "quic":
		co := network.NewUDPPacketConn(nomination.Conn.(*net.UDPConn))
		l, err = qt.GetListenerFromConn(ctx, co, cfg, tlsConfig)
	case "ws":
		l, err = ws.GetListenerFromConn(ctx, nomination.Conn, cfg, tlsConfig)
	case "dtls":
		co := network.NewUDPPacketConn(nomination.Conn.(*net.UDPConn))
		l, err = dtls.GetListenerFromConn(ctx, co, cfg, tlsConfig, mtu)
	case "tls":
		l, err = trtls.GetListenerFromConn(ctx, nomination.Conn, cfg, tlsConfig)
	case "tls-in-icmp":
		l, err = tlsicmp.GetListenerFromConn(ctx, nomination.Conn, cfg, tlsConfig)
	}
	if err != nil {
		c.logger.Errorf("Failed to get listener for %s: %v", nomination.String(), err)
		return
	}
	c.logger.Infof("ICE completed | %s", nomination.String())
	pigListener.Load(l) //nolint:errcheck
}

func (c *Controller) connectICEListenPath(ctx context.Context, cp *ice.ConnectPath, bindAdapter string, connectedPaths *sync.Map) {
	c.logger.Debugf("Connecting ICE path | %s", cp.String())
	_, e := cp.Connect()
	if e == ice.ErrConnectICMP {
		_, e = cp.ConnectICMP(ctx, c.logger, bindAdapter, true)
	}
	if e != nil {
		c.logger.Tracef("Failed to connect ICE path %s: %v", cp.String(), e)
		return
	}
	if cp.Protocol.Network != "icmp" {
		cp.BindAgent.SendRequest(true) //nolint:errcheck // it's okay for this to fail
	}
	connectedPaths.Store(cp.String(), cp)
}
