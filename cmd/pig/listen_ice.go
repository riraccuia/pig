package main

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
	"github.com/riraccuia/pig/pkg/ice/conn"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/transport"
	"github.com/riraccuia/pig/pkg/transport/dtls"
	qt "github.com/riraccuia/pig/pkg/transport/quic-go"
	trtls "github.com/riraccuia/pig/pkg/transport/tls"
	"github.com/riraccuia/pig/pkg/transport/tlsicmp"
	"github.com/riraccuia/pig/pkg/transport/ws"
)

func getICEListenFunc(ctx context.Context, logger *log.Logger, cfg *config.Config) (func() (transport.Listener, error), error) {
	listenPort := uint16(cfg.Target.Port)
	if listenPort == 0 {
		// use a random port
		listenPort = uint16(rand.Intn(65535-1024) + 1024)
	}
	logger.Infof("Starting ICE | Candidate protocols: %v | Listen port: %d", strings.Join(cfg.ICE.Protos, ", "), listenPort)
	return func() (transport.Listener, error) {
		listenPathsChan, err := ice.GetListenPaths(ctx, signaling.GetOptions(logger, cfg.ICE), listenPort, cfg.ICE.UseProtos())
		if err != nil {
			return nil, fmt.Errorf("failed to get listen paths: %w", err)
		}
		tlsConfig, err := createTLSConfig(logger, cfg)
		if err != nil {
			logger.Errorf("failed to create TLS config: %v", err)
			return nil, err
		}
		iceListener := ice.NewListener(ctx, nil)
		go receiveICEServerConnectPaths(ctx, logger, cfg, tlsConfig, listenPathsChan, iceListener)
		return iceListener, nil
	}, nil
}

func receiveICEServerConnectPaths(ctx context.Context, logger *log.Logger, cfg *config.Config, tlsConfig *tls.Config, listenPathsChan <-chan []*ice.ConnectPath, pigListener *ice.Listener) {
	for {
		//logger.Debugf("Waiting for listen paths")
		select {
		case <-ctx.Done():
			logger.Errorf("Aborting listen paths processor: %v", ctx.Err())
			return
		case listenPaths := <-listenPathsChan:
			go processICEServerConnectPaths(ctx, logger, cfg, tlsConfig, listenPaths, pigListener)
		}
	}
}

func processICEServerConnectPaths(ctx context.Context, logger *log.Logger, cfg *config.Config, tlsConfig *tls.Config, listenPaths []*ice.ConnectPath, pigListener *ice.Listener) {
	var (
		err            error
		connectedPaths = &sync.Map{}
		timer          = time.NewTimer(time.Second * 10)
		nomination     *ice.ConnectPath
	)
	for _, cp := range listenPaths {
		logger.Debugf("Connecting ICE path | %s", cp.String())
		go func(cp *ice.ConnectPath) {
			_, e := cp.Connect()
			if e == ice.ErrConnectICMP {
				_, e = cp.ConnectICMP(ctx, logger, cfg.BindAdapter, true)
			}
			if e != nil {
				logger.Tracef("Failed to connect ICE path %s: %v", cp.String(), e)
				return
			}
			if cp.Protocol.Network != "icmp" {
				cp.BindAgent.SendBindingRequest(true) // it's okay for this to fail
			}
			cp.BindAgent.Receive() // keep on handling binding requests until ice is completed
			connectedPaths.Store(cp.String(), cp)
		}(cp)
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
			if cp.BindAgent.IsNominated() {
				nomination = cp
				nomination.BindAgent.StopReceive()
			}
			return true
		})
		if nomination != nil {
			break
		}
		time.Sleep(time.Millisecond * 10)
	}
	for _, cp := range listenPaths {
		if nomination == nil || cp != nomination {
			cp.CloseConn()
		}
	}
	if nomination == nil {
		return
	}

	logger.Infof("ICE candidate nominated: %s", nomination.String())

	var l transport.Listener
	switch nomination.Protocol.Protocol {
	case "quic":
		co := conn.NewUDPPacketConn(nomination.Conn.(*net.UDPConn))
		l, err = qt.GetListenerFromConn(ctx, co, cfg, tlsConfig)
	case "ws":
		l, err = ws.GetListenerFromConn(ctx, nomination.Conn, cfg, tlsConfig)
	case "dtls":
		co := conn.NewUDPPacketConn(nomination.Conn.(*net.UDPConn))
		l, err = dtls.GetListenerFromConn(ctx, co, cfg, tlsConfig)
	case "tls":
		l, err = trtls.GetListenerFromConn(ctx, nomination.Conn, cfg, tlsConfig)
	case "tls-in-icmp":
		l, err = tlsicmp.GetListenerFromConn(ctx, nomination.Conn, cfg, tlsConfig)
	}
	if err != nil {
		logger.Errorf("Failed to get listener for %s: %v", nomination.String(), err)
		return
	}
	logger.Infof("ICE completed | %s", nomination.String())
	pigListener.Load(l)
}
