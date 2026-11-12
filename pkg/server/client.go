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

package server

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/queue"
	"github.com/riraccuia/pig/pkg/streams"
	"github.com/riraccuia/pig/pkg/transport"
)

// ClientTunnel represents a client connection.
type ClientTunnel struct {
	parent              *Server
	logger              common.Logger
	conn                transport.Conn
	streams             *streams.StreamManager
	sourceIP, sourceIP6 net.IP
	outbound            *queue.FIFO[network.IPPacket]
	dropLogger          *common.DelayedCounterProcessor
	connError           chan error
	cancel              context.CancelFunc
	wg, outWg           sync.WaitGroup
	closed              atomic.Bool
}

func (s *Server) performAuthentication(ctx context.Context, conn transport.Conn) (err error) {
	// Perform authentication if enabled
	if s.authenticator == nil {
		return
	}
	if err = s.authenticator.Authenticate(ctx, conn); err != nil {
		s.logger.Errorf("Client authentication failed: %v", err)
		return err
	}
	s.logger.Infof("Client authenticated successfully: %s", conn.RemoteAddr())
	return nil
}

// handleNewClient handles a new client connection.
func (s *Server) handleNewClient(ctx context.Context, conn transport.Conn) (ok bool) {
	logger := s.logger.WithFields([]common.LoggerField{
		{
			Key:   "client",
			Value: conn.RemoteAddr().String(),
		},
	})

	// Allocate IP for the client
	sourceIP, err := s.AllocateIP()
	if err != nil {
		logger.Errorf("Failed to allocate IP for client %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	sourceIP6, err := s.AllocateIP6()
	if err != nil {
		logger.Errorf("Failed to allocate IP6 for client %s: %v", conn.RemoteAddr(), err)
	}

	client := NewClientTunnel(ctx, s).WithLogger(logger)
	client.Start(ctx, conn, sourceIP, sourceIP6)

	// Store client in sync.Map using sourceIP as key
	client.parent.clients.Store(sourceIP.String(), client)
	if sourceIP6 != nil {
		client.parent.clients.Store(sourceIP6.String(), client)
	}

	go func() {
		select {
		case <-ctx.Done():
			client.logger.Info("disconnecting (context done)")
		case err := <-client.connError:
			client.logger.Errorf("connection error: %v", err)
		}
		client.Close()
		if s.acceptOnce {
			s.Close()
		}
	}()

	return true
}

func NewClientTunnel(ctx context.Context, parent *Server) *ClientTunnel {
	outbound := queue.NewFIFO[network.IPPacket](parent.adapterCfg.QueueSize)
	if parent.config.Wred.MaxDropProbability > 0 {
		outbound = outbound.WithWRED(parent.config.Wred.WeightFactor, parent.config.Wred.MaxDropProbability, parent.config.Wred.MinThreshold, parent.config.Wred.MaxThreshold)
		/*parent.logger.Infof("WRED enabled for client %s with weight factor: %d, drop probability: %d%%, threshold avg queue len: %d%%",
			conn.RemoteAddr(),
			int(parent.config.Wred.WeightFactor),
			int(parent.config.Wred.DropProbability*100),
			int(parent.config.Wred.Threshold*100),
		)*/
	}

	client := &ClientTunnel{
		parent:    parent,
		logger:    parent.logger, // this will be a child logger for the client, e.g. with a prefix
		streams:   streams.New(),
		outbound:  outbound,
		connError: make(chan error, 1),
	}
	return client
}

func (client *ClientTunnel) WithLogger(logger common.Logger) *ClientTunnel {
	client.logger = logger
	return client
}

func (client *ClientTunnel) Start(ctx context.Context, conn transport.Conn, sourceIP, sourceIP6 net.IP) {
	ctx, cancel := context.WithCancel(ctx)

	client.cancel = cancel
	client.conn = conn
	client.sourceIP = sourceIP
	client.sourceIP6 = sourceIP6

	if client.dropLogger == nil {
		client.dropLogger = common.NewDelayedCounterProcessor(func(c1, c2 *atomic.Uint64) {
			client.logger.Infof("Dropped %d packets (%d bytes)", c1.Load(), c2.Load())
		}).WithBackoff(time.Second, time.Second*15)
		client.dropLogger.Start(ctx)
	}

	client.logger.Infof("allocated IP: %s, allocated IP6: %s", sourceIP.String(), sourceIP6.String())

	switch conn.IsStreamed() {
	case true:
		client.wg.Go(func() { client.acceptStreams(ctx) })
	case false:
		client.wg.Go(func() { client.handleInbound(ctx, conn) })
	}

	client.outWg.Go(func() { client.handleOutbound() })
}

func (client *ClientTunnel) Close() {
	// Execute stop script
	/*s.scriptExecutor.ExecuteStopScript(script.ScriptContext{
		TunnelName:  s.adapter.Name(),
		TunnelIndex: s.adapter.Index(),
		RemoteAddr:  client.conn.RemoteAddr().String(),
		NatAddr:     client.sourceIP.String(),
		TunnelProto: string(s.config.Proto),
	})*/

	if !client.closed.CompareAndSwap(false, true) {
		return
	}

	client.outbound.Close()
	client.outWg.Wait()

	client.cancel()
	client.conn.Close()
	client.streams.CloseAll()

	queue.DrainQueue(client.outbound, func(pkt network.IPPacket) {
		client.parent.bufferPool.PutBuffer(pkt.Bytes())
	})

	client.parent.ReleaseIP(client.sourceIP)
	client.parent.ReleaseIP6(client.sourceIP6)
	client.parent.clients.Delete(client.sourceIP.String())
	client.parent.clients.Delete(client.sourceIP6.String())

	client.wg.Wait()

	client.logger.Info("closed")
}
