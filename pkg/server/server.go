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
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/riraccuia/pig/pkg/adapter"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/transport"
)

// Server represents a tunnel server that handles multiple client connections.
type Server struct {
	logger          common.Logger
	config          *config.TunnelConfig
	adapterCfg      *config.AdapterConfig
	adapter         common.TunnelAdapter
	listener        transport.Listener
	clients         *sync.Map
	ipPool, ipPool6 *IPPool
	bufferPool      *sync.Pool
	inbound         []common.PacketQueue
	outbound        common.PacketQueue
	done            chan struct{}
	authenticator   common.Authenticator
	_next_queue_id  atomic.Uint64
	closed          atomic.Bool
}

// New creates a new Server instance with its own TUN adapter.
func New(logger common.Logger, adapterCfg *config.AdapterConfig, tunnelCfg *config.TunnelConfig, authenticator common.Authenticator) (*Server, error) {
	a, err := adapter.NewAdapter(adapter.AdapterConfig{
		Address: adapterCfg.TunnelAddress,
		MTU:     adapterCfg.MTU,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create adapter: %w", err)
	}
	return NewWithAdapter(logger, adapterCfg, tunnelCfg, a, authenticator)
}

// NewWithAdapter creates a new Server instance with a caller-supplied adapter.
func NewWithAdapter(logger common.Logger, adapterCfg *config.AdapterConfig, tunnelCfg *config.TunnelConfig, adapter common.TunnelAdapter, authenticator common.Authenticator) (*Server, error) {
	logger.Infof("Creating server with adapter %s, IP: %s, MTU %d", adapter.Name(), adapter.IP(), adapterCfg.MTU)
	queueSize := adapterCfg.QueueSize
	if queueSize <= 0 {
		queueSize = config.DefaultQueueSize
	}
	s := &Server{
		logger:     logger,
		config:     tunnelCfg,
		adapterCfg: adapterCfg,
		adapter:    adapter,
		clients:    &sync.Map{},
		outbound:   make(common.PacketQueue, queueSize),
		bufferPool: &sync.Pool{
			New: func() any {
				return make([]byte, adapterCfg.MTU)
			},
		},
		done:          make(chan struct{}),
		authenticator: authenticator,
	}
	s.buildIPPool(adapter)
	return s, nil
}

func (s *Server) Start(ctx context.Context, listenFunc func(ctx context.Context) (transport.Listener, error)) error {
	if !s.closed.CompareAndSwap(false, true) {
		return fmt.Errorf("server already started")
	}

	s.logger.Info("Starting server")

	listener, err := listenFunc(ctx)
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	s.listener = listener
	s.done = make(chan struct{})

	s.logger.Infof("Listening on %s:%d", s.config.Listen.Address, s.config.Listen.Port)

	go s.acceptClients(ctx)
	go s.processInbound(ctx)
	// go s.processOutbound(ctx)
	go s.readFromAdapter()

	return nil
}

// GetAdapter returns the adapter.
func (s *Server) GetAdapter() common.TunnelAdapter {
	return s.adapter
}

func (s *Server) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return fmt.Errorf("server already closed")
	}

	defer close(s.done)

	// Close all client connections
	s.clients.Range(func(key any, value any) bool {
		if client, ok := value.(*ClientTunnel); ok {
			client.streams.CloseAll()
			client.conn.Close()
			s.ipPool.Release(client.sourceIP)
		}
		return true
	})

	// Clear the clients map
	s.clients.Clear()

	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *Server) WaitClose() {
	if s.closed.Load() {
		return
	}
	<-s.done
}

func (s *Server) buildIPPool(adapter common.TunnelAdapter) {
	ipNet := adapter.IPNet()
	s.logger.Infof("Building IP pool for IPv4 network: %s", ipNet.String())
	s.ipPool = newIPPool(ipNet)
	ipNet6 := adapter.IPNet6()
	s.logger.Infof("Building IP pool for IPv6 network: %s", ipNet6.String())
	s.ipPool6 = newIPPool(ipNet6)
}

func (s *Server) AllocateIP() (net.IP, error) {
	return s.ipPool.Allocate()
}

func (s *Server) AllocateIP6() (net.IP, error) {
	return s.ipPool6.Allocate()
}

func (s *Server) ReleaseIP(ip net.IP) {
	s.ipPool.Release(ip)
}

func (s *Server) ReleaseIP6(ip net.IP) {
	s.ipPool6.Release(ip)
}
