package controller

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/ice/conn"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/transport"
	"github.com/riraccuia/pig/pkg/transport/dtls"
	qt "github.com/riraccuia/pig/pkg/transport/quic-go"
	trtls "github.com/riraccuia/pig/pkg/transport/tls"
	"github.com/riraccuia/pig/pkg/transport/tlsicmp"
	"github.com/riraccuia/pig/pkg/transport/ws"
)

func (c *Controller) getICEDialFunc(ctx context.Context, cfg *config.TunnelConfig) (func() (transport.Conn, error), error) {
	tlsConfig, err := c.createTLSConfig(config.ModeClient, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}
	return func() (transport.Conn, error) {
		c.logger.Infof("Starting ICE | Candidate protocols: %v", strings.Join(cfg.ICE.Protos, ", "))
		connectPaths, err := ice.GetConnectPaths(ctx, signaling.GetOptions(c.logger, cfg.ICE), &cfg.Target, cfg.ICE.UseProtos())
		if err != nil {
			return nil, fmt.Errorf("failed to get ICE connect paths: %w", err)
		}
		if len(connectPaths) == 0 {
			return nil, fmt.Errorf("no ICE candidates found")
		}

		selectedPath, err := processICEClientConnectPaths(ctx, c.logger, cfg, connectPaths)
		if err != nil {
			return nil, fmt.Errorf("failed to process ICE client connect paths: %w", err)
		}

		c.logger.Debugf("ICE connect path nominated: %s", selectedPath.String())

		selectedPath.BindAgent.StopReceive()
		selectedPath.BindAgent.Ice.UseCandidate = true
		// send the last binding request to tell the other side
		// that we are going to use this candidate
		_, err = selectedPath.BindAgent.SendBindingRequest(true)
		if err != nil {
			return nil, fmt.Errorf("failed to send binding request: %w", err)
		}

		c.logger.Infof("ICE completed | %s", selectedPath.String())

		// Allow the server to set up the listening side of the connection
		time.Sleep(time.Millisecond * 50)

		switch selectedPath.Protocol.Protocol {
		case "ws":
			return ws.GetClientFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
		case "quic":
			co := conn.NewUDPPacketConn(selectedPath.Conn.(*net.UDPConn))
			return qt.GetClientFromConn(ctx, co, cfg, tlsConfig)
		case "dtls":
			co := conn.NewUDPPacketConn(selectedPath.Conn.(*net.UDPConn))
			co.SetReadBuffer(1024 * 2048)
			co.SetWriteBuffer(1024 * 2048)
			return dtls.GetClientFromConn(ctx, co, cfg, tlsConfig)
		case "tls":
			return trtls.GetClientFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
		case "tls-in-icmp":
			return tlsicmp.GetClientFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
		}
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
	}, nil
}

func processICEClientConnectPaths(ctx context.Context, logger common.Logger, cfg *config.TunnelConfig, connectPaths []*ice.ConnectPath) (selectedPath *ice.ConnectPath, err error) {
	var (
		selectedPtr = atomic.Pointer[ice.ConnectPath]{}
		timer       = time.NewTimer(time.Second * 10)
	)
	sort.SliceStable(connectPaths, func(i, j int) bool {
		return connectPathPriority(connectPaths[i]) > connectPathPriority(connectPaths[j])
	})
	for _, cp := range connectPaths {
		logger.Debugf("Connecting ICE path | %s | Scheduled at: %s", cp.String(), cp.ScheduledAt.UTC().Format(time.RFC3339))
		time.AfterFunc(time.Until(cp.ScheduledAt), func() {
			_, e := cp.Connect()
			if e == ice.ErrConnectICMP {
				_, e = cp.ConnectICMP(ctx, logger, cfg.BindAdapter, false)
			}
			if e != nil {
				logger.Tracef("Failed to connect ICE path %s: %v", cp.String(), e)
				return
			}
			e = cp.ICESetup()
			if e != nil {
				cp.CloseConn()
				//logger.Tracef("Failed to ICE bind path %s: %v", cp.String(), e)
				return
			}
			if !selectedPtr.CompareAndSwap(nil, cp) {
				cp.CloseConn()
			}
		})
	}
	var stop bool
	for !stop {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			stop = true
		case <-timer.C:
			err = fmt.Errorf("ICE timed out")
			stop = true
		default:
			// continue with the logic
		}
		selectedPath = selectedPtr.Load()
		if selectedPath != nil {
			break
		}
		time.Sleep(time.Millisecond * 10)
	}
	// close all connect paths that are not the selected path
	for _, cp := range connectPaths {
		if selectedPath == nil || cp != selectedPath {
			cp.CloseConn()
		}
	}
	return
}

func connectPathPriority(cp *ice.ConnectPath) uint32 {
	if cp == nil {
		return 0
	}
	if cp.BindAgent == nil {
		return 0
	}
	if cp.BindAgent.Ice == nil {
		return 0
	}
	return cp.BindAgent.Ice.Priority
}
