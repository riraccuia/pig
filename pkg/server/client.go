package server

import (
	"context"
	"net"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/queue"
	"github.com/riraccuia/pig/pkg/queue/wred"
	"github.com/riraccuia/pig/pkg/streams"
	"github.com/riraccuia/pig/pkg/transport"
)

type ClientTunnel struct {
	conn      transport.Conn
	streams   *streams.StreamManager
	sourceIP  net.IP
	inbound   common.PacketQueue
	outbound  *queue.ChanQueue
	connError chan error
	cancel    context.CancelFunc
}

func (s *Server) handleNewClient(ctx context.Context, conn transport.Conn) {
	sourceIP, err := s.ipPool.Allocate()
	if err != nil {
		conn.Close()
		return
	}

	clientCtx, cancel := context.WithCancel(ctx)

	outbound := queue.NewChanQueue(common.QueueSize)
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
		conn:      conn,
		streams:   streams.New(),
		sourceIP:  sourceIP,
		inbound:   make(common.PacketQueue, common.QueueSize),
		outbound:  outbound,
		connError: make(chan error, 1),
		cancel:    cancel,
	}

	s.clients.Store(client.sourceIP.String(), client)

	s.logger.Infof("New client connected from %s, allocated IP: %s", client.conn.RemoteAddr(), client.sourceIP.String())

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
	client.cancel()
	client.conn.Close()
	client.streams.CloseAll()
	s.clients.Delete(client.sourceIP.String())
}
