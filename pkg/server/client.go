package server

import (
	"context"
	"net"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/queue"
	"github.com/riraccuia/pig/pkg/queue/wred"
	"github.com/riraccuia/pig/pkg/script"
	"github.com/riraccuia/pig/pkg/streams"
	"github.com/riraccuia/pig/pkg/transport"
)

// ClientTunnel represents a client connection
type ClientTunnel struct {
	conn       transport.Conn
	streams    *streams.StreamManager
	sourceIP   net.IP
	inbound    common.PacketQueue
	outbound   *queue.ChanQueue
	dropLogger *common.DelayedCounterProcessor
	connError  chan error
	cancel     context.CancelFunc
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

// handleNewClient handles a new client connection
func (s *Server) handleNewClient(ctx context.Context, conn transport.Conn) {
	// Allocate IP for the client
	sourceIP, err := s.ipPool.Allocate()
	if err != nil {
		s.logger.Errorf("Failed to allocate IP for client %s: %v", conn.RemoteAddr(), err)
		conn.Close()
		return
	}

	clientCtx, cancel := context.WithCancel(ctx)

	outbound := queue.NewChanQueue(s.config.QueueSize)
	if s.config.Wred.DropProbability > 0 {
		wred, err := wred.NewWRED(s.config.Wred.WeightFactor)
		if err != nil {
			s.logger.Errorf("failed to create WRED: %w", err)
		}
		s.logger.Infof("WRED enabled for client %s with weight factor: %d, drop probability: %d%%, threshold avg queue len: %d%%",
			conn.RemoteAddr(),
			int(s.config.Wred.WeightFactor),
			int(s.config.Wred.DropProbability*100),
			int(s.config.Wred.Threshold*100),
		)
		outbound = outbound.WithWRED(wred, s.config.Wred.DropProbability, s.config.Wred.Threshold)
	}

	client := &ClientTunnel{
		conn:     conn,
		streams:  streams.New(),
		sourceIP: sourceIP,
		inbound:  make(common.PacketQueue, s.config.QueueSize),
		outbound: outbound,
		dropLogger: common.NewDelayedCounterProcessor(func(c1, c2 *atomic.Uint64) {
			s.logger.Infof("Client %s dropped %d packets (%d bytes)", conn.RemoteAddr(), c1.Load(), c2.Load())
		}).WithBackoff(time.Second, time.Second*15),
		connError: make(chan error, 1),
		cancel:    cancel,
	}

	client.dropLogger.Start(clientCtx)

	// Store client in sync.Map using sourceIP as key
	s.clients.Store(client.sourceIP.String(), client)

	s.logger.Infof("New client connected from %s, allocated IP: %s", client.conn.RemoteAddr(), client.sourceIP.String())

	// Execute start script
	s.scriptExecutor.ExecuteStartScript(script.ScriptContext{
		TunnelName:  s.adapter.Name(),
		TunnelIndex: s.adapter.Index(),
		RemoteAddr:  conn.RemoteAddr().String(),
		NatAddr:     sourceIP.String(),
		TunnelProto: string(s.config.Proto),
	})

	go s.manageClient(clientCtx, client)

	defer s.handleOutbound(clientCtx, client)

	if !client.conn.IsStreamed() {
		go s.handleInbound(client, client.conn)
		return
	}

	go s.acceptStreams(clientCtx, client)
}

func (s *Server) manageClient(ctx context.Context, client *ClientTunnel) {
	select {
	case <-ctx.Done():
	case <-s.done:
	case err := <-client.connError:
		s.logger.Errorf("client %s lost: %v", client.conn.RemoteAddr(), err)
	}
	s.closeClient(client)
}

func (s *Server) closeClient(client *ClientTunnel) {
	// Execute stop script
	s.scriptExecutor.ExecuteStopScript(script.ScriptContext{
		TunnelName:  s.adapter.Name(),
		TunnelIndex: s.adapter.Index(),
		RemoteAddr:  client.conn.RemoteAddr().String(),
		NatAddr:     client.sourceIP.String(),
		TunnelProto: string(s.config.Proto),
	})

	client.cancel()
	client.conn.Close()
	client.streams.CloseAll()
	s.clients.Delete(client.sourceIP.String())
}
