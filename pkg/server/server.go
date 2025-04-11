package server

import (
	"context"
	"fmt"
	"net"
	"sync"

	"github.com/riraccuia/pig/pkg/adapter"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/packet"
	"github.com/riraccuia/pig/pkg/script"
	"github.com/riraccuia/pig/pkg/transport"
)

// Server represents a tunnel server that handles multiple client connections
type Server struct {
	logger         common.Logger
	config         *config.Config
	adapter        common.TunnelAdapter
	listener       transport.Listener
	clients        *sync.Map //*ash.Map
	ipPool         *IPPool
	bufferPool     *sync.Pool
	inbound        common.PacketQueue
	outbound       common.PacketQueue
	done           chan struct{}
	scriptExecutor *script.Executor
	authenticator  common.Authenticator
}

// New creates a new Server instance
func New(logger common.Logger, cfg *config.Config, authenticator common.Authenticator) (*Server, error) {
	adapter, err := adapter.NewAdapter(cfg)
	if err != nil {
		return nil, err
	}
	return NewWithAdapter(logger, cfg, adapter, authenticator)
}

// NewWithAdapter creates a new Server instance with a custom network adapter
func NewWithAdapter(logger common.Logger, cfg *config.Config, adapter common.TunnelAdapter, authenticator common.Authenticator) (*Server, error) {
	logger.Infof("Creating server with adapter %s, IP: %s, MTU %d", adapter.Name(), adapter.IP(), cfg.MTU)
	_, network, err := net.ParseCIDR(cfg.TunnelAddress)
	if err != nil {
		return nil, err
	}

	if cfg.QueueSize <= 0 {
		cfg.QueueSize = common.DefaultQueueSize
	}

	return &Server{
		logger:   logger,
		config:   cfg,
		adapter:  adapter,
		clients:  &sync.Map{}, //new(ash.Map).From(ash.NewSkipList(32)),
		ipPool:   newIPPool(network),
		inbound:  make(common.PacketQueue, cfg.QueueSize),
		outbound: make(common.PacketQueue, cfg.QueueSize),
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make(packet.IPv4Packet, cfg.MTU, cfg.MTU)
			},
		},
		done:           make(chan struct{}),
		scriptExecutor: script.New(logger, cfg),
		authenticator:  authenticator,
	}, nil
}

func (s *Server) Start(ctx context.Context, listenFunc func() (transport.Listener, error)) error {
	s.logger.Info("Starting server")

	listener, err := listenFunc()
	if err != nil {
		return fmt.Errorf("failed to create listener: %w", err)
	}
	s.listener = listener
	s.done = make(chan struct{})

	s.logger.Infof("Listening on %s:%d", s.config.Target.Address, s.config.Target.Port)

	go s.acceptClients(ctx)
	go s.processInboundQueue(ctx)
	go s.processOutboundQueue(ctx)
	go s.readFromAdapter()

	return nil
}

// GetAdapter returns the adapter
func (s *Server) GetAdapter() common.TunnelAdapter {
	return s.adapter
}

func (s *Server) Close() error {
	if s.done != nil {
		close(s.done)
	}

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
