package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/ice/conn"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/transport"
	qt "github.com/riraccuia/pig/pkg/transport/quic-go"
	"github.com/riraccuia/pig/pkg/transport/ws"
)

func getICEDialFunc(ctx context.Context, logger *log.Logger, cfg *config.Config) (func() (transport.Conn, error), error) {
	tlsConfig, err := createTLSConfig(logger, cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS config: %w", err)
	}
	return func() (transport.Conn, error) {
		logger.Infof("Starting ICE | Candidate protocols: %v", strings.Join(cfg.ICE.Protos, ", "))
		connectPaths, err := ice.GetConnectPaths(ctx, signaling.GetOptions(logger, cfg.ICE), cfg.Target.Address, cfg.ICE.UseProtos())
		if err != nil {
			return nil, fmt.Errorf("failed to get ICE connect paths: %w", err)
		}
		if len(connectPaths) == 0 {
			return nil, fmt.Errorf("no ICE candidates found")
		}

		selectedPath, err := processICEClientConnectPaths(ctx, logger, connectPaths)
		if err != nil {
			return nil, fmt.Errorf("failed to process ICE client connect paths: %w", err)
		}

		logger.Debugf("ICE connect path nominated: %s", selectedPath.String())

		selectedPath.BindAgent.StopReceive()
		selectedPath.BindAgent.Ice.UseCandidate = true
		// send the last binding request to tell the other side
		// that we are going to use this candidate
		_, err = selectedPath.BindAgent.SendBindingRequest(true)
		if err != nil {
			//logger.Errorf("Failed to send USE-CANDIDATE attribute to %s: %v", selectedPath.String(), err)
			return nil, fmt.Errorf("failed to send binding request: %w", err)
		}

		logger.Infof("ICE completed | %s", selectedPath.String())

		switch selectedPath.Protocol.Protocol {
		case "ws":
			return ws.GetClientFromConn(ctx, selectedPath.Conn, cfg, tlsConfig)
		case "quic":
			co := conn.NewUDPPacketConn(selectedPath.Conn.(*net.UDPConn))
			return qt.GetClientFromConn(ctx, co, cfg, tlsConfig)
		}
		return nil, fmt.Errorf("unsupported transport type: %s", cfg.Proto)
	}, nil
}

func processICEClientConnectPaths(ctx context.Context, logger *log.Logger, connectPaths []*ice.ConnectPath) (selectedPath *ice.ConnectPath, err error) {
	var (
		selectedPtr = atomic.Pointer[ice.ConnectPath]{}
		timer       = time.NewTimer(time.Second * 10)
	)
	for _, cp := range connectPaths {
		logger.Debugf("Connecting ICE path | %s", cp.String())
		go func(cp *ice.ConnectPath) {
			_, e := cp.Connect()
			if e != nil {
				//logger.Errorf("Failed to connect ICE path %s: %v", cp.String(), e)
				return
			}
			e = cp.ICESetup()
			if e != nil {
				cp.CloseConn()
				//logger.Errorf("Failed to ICE bind path %s: %v", cp.String(), e)
				return
			}
			if !selectedPtr.CompareAndSwap(nil, cp) {
				cp.CloseConn()
			}
		}(cp)
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
