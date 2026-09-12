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

package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/adapter"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/queue"
	"github.com/riraccuia/pig/pkg/queue/wred"
	"github.com/riraccuia/pig/pkg/streams"
	"github.com/riraccuia/pig/pkg/transport"
)

// Client represents a tunnel client that handles traffic between
// a local network adapter and a remote server.
type Client struct {
	logger            common.Logger
	dropLogger        *common.DelayedCounterProcessor
	config            *config.TunnelConfig
	conn              transport.Conn
	streams           *streams.StreamManager
	adapter           common.TunnelAdapter
	inbound           common.PacketQueue
	outbound          *queue.ChanQueue
	bufferPool        common.BufferPool
	done              chan struct{}
	closed            atomic.Bool
	reconnectInterval time.Duration
	connError         chan error
	authenticator     common.Authenticator
	events            chan *EventContext
	mtu               int
	state             atomic.Int32
	peerAddr          atomic.Value
	mappedIPs         *sync.Map
	conntrack         *Conntrack
}

type atomicAddr struct {
	net.Addr
}

// New creates a new Client instance with its own TUN adapter.
// Use this for standalone / single-tunnel operation where the caller does not
// manage the adapter externally.
func New(logger common.Logger, adapterCfg *config.AdapterConfig, tunnelCfg *config.TunnelConfig, authenticator common.Authenticator) (*Client, error) {
	a, err := adapter.NewAdapter(adapter.AdapterConfig{
		Address: adapterCfg.TunnelAddress,
		MTU:     adapterCfg.MTU,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create adapter: %w", err)
	}
	return NewWithAdapter(logger, adapterCfg, tunnelCfg, a, authenticator)
}

// NewWithAdapter creates a new Client instance with a caller-supplied adapter.
// In the multi-tunnel case the controller passes a per-tunnel virtual adapter
// (tunnelAdapter) so that reads only deliver packets routed to this tunnel.
func NewWithAdapter(logger common.Logger, adapterCfg *config.AdapterConfig, tunnelCfg *config.TunnelConfig, adapter common.TunnelAdapter, authenticator common.Authenticator) (*Client, error) {
	logger.Infof("Creating client with adapter %s, IP: %s, MTU %d", adapter.Name(), adapter.IP(), adapterCfg.MTU)

	queueSize := adapterCfg.QueueSize
	if queueSize <= 0 {
		queueSize = config.DefaultQueueSize
	}

	outbound := queue.NewChanQueue(queueSize)
	if tunnelCfg.Wred.DropProbability > 0 {
		wred, err := wred.NewWRED(tunnelCfg.Wred.WeightFactor)
		if err != nil {
			return nil, fmt.Errorf("failed to create WRED: %w", err)
		}
		logger.Infof("WRED enabled with weight factor: %d, drop probability: %d%%, threshold avg queue len: %d%%", int(tunnelCfg.Wred.WeightFactor), int(tunnelCfg.Wred.DropProbability*100), int(tunnelCfg.Wred.Threshold*100))
		outbound = outbound.WithWRED(wred, tunnelCfg.Wred.DropProbability, tunnelCfg.Wred.Threshold)
	}

	cl := &Client{
		logger:            logger,
		config:            tunnelCfg,
		streams:           streams.New(),
		adapter:           adapter,
		inbound:           make(common.PacketQueue, queueSize),
		outbound:          outbound,
		bufferPool:        common.DefaultBufferPool,
		done:              make(chan struct{}),
		mtu:               adapterCfg.MTU,
		reconnectInterval: time.Duration(tunnelCfg.ReconnectInterval) * time.Second,
		connError:         make(chan error, 1),
		authenticator:     authenticator,
		events:            make(chan *EventContext, 10),
		mappedIPs:         &sync.Map{},
	}
	return cl, nil
}

func (c *Client) WithBufferPool(bufferPool common.BufferPool) *Client {
	c.bufferPool = bufferPool
	return c
}

// Start initializes the client connection and starts all necessary goroutines
// for handling traffic. The dialFunc parameter provides the connection to the server.
func (c *Client) Start(ctx context.Context, dialFunc func(ctx context.Context) (transport.Conn, error)) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	c.conntrack = NewConntrack()

	c.logger.Infof("Starting client with reconnect interval %d seconds", c.reconnectInterval/time.Second)

	if c.dropLogger == nil {
		c.dropLogger = common.NewDelayedCounterProcessor(func(c1, c2 *atomic.Uint64) {
			c.logger.Infof("Dropped %d packets (%d bytes)", c1.Load(), c2.Load())
		}).WithBackoff(time.Second, time.Second*15)
		c.dropLogger.Start(ctx)
	}

	c.resetClosed()

	go c.readFromAdapter(ctx)
	go c.manageConnection(ctx, dialFunc)

	return nil
}

func (c *Client) manageConnection(ctx context.Context, dialFunc func(ctx context.Context) (transport.Conn, error)) {
	for {
		c.logger.Infof("Connecting to target...")
		conn, err := dialFunc(ctx)
		if err != nil {
			c.logger.Errorf("Failed to connect to target: %v", err)
			select {
			case <-ctx.Done():
				c.closeWithEvent(&EventContext{State: StateStopped})
				c.logger.Infof("Context done, exiting")
				return
			case <-time.After(c.reconnectInterval):
				c.signalEvent(&EventContext{State: StateConnectionFailed, Error: err})
				c.logger.Error("Retrying connection...")
				continue
			}
		}

		// Perform authentication if configured
		if c.authenticator != nil {
			if err := c.authenticator.Authenticate(ctx, conn); err != nil {
				c.logger.Errorf("Failed to authenticate: %v", err)
				c.signalEvent(&EventContext{State: StateConnectionFailed, Error: err})
				conn.Close()
				continue
			}
		}

		c.drainQueues()
		c.conn = conn

		go c.writeToAdapter(ctx)
		go c.handleInbound(ctx)
		go c.handleOutbound(ctx)

		c.logger.Infof("Connected to %s", conn.RemoteAddr())
		c.signalEvent(&EventContext{State: StateConnected, Conn: conn})

		select {
		case <-c.done:
			c.logger.Infof("Client stopped")
			return
		case <-ctx.Done():
			c.logger.Infof("Context done, exiting")
			c.closeWithEvent(&EventContext{State: StateStopped, Conn: c.conn})
			return
		case err := <-c.connError:
			c.logger.Errorf("Connection lost: %v", err)
			c.closeWithEvent(&EventContext{State: StateDisconnected, Conn: c.conn, Error: err})
			return
		}
	}
}

func (c *Client) Name() string {
	return c.config.Name
}

func (c *Client) WaitClose() {
	<-c.done
}

// Close gracefully shuts down the client and all its goroutines.
func (c *Client) Close() error {
	return c.closeWithEvent(&EventContext{State: StateStopped, Conn: c.conn})
}

func (c *Client) closeWithEvent(event *EventContext) error {
	if c.closed.CompareAndSwap(false, true) {
		if event != nil {
			c.signalEvent(event)
		}
		c.state.Store(int32(StateStopped))
		c.streams.CloseAll()
		if c.conn != nil {
			c.conn.Close()
			c.conn = nil
		}
		c.conntrack.Close()
		close(c.done)
	}
	return nil
}

// Config returns the tunnel configuration.
func (c *Client) Config() *config.TunnelConfig { return c.config }

// PeerAddr returns the remote address when connected, or nil otherwise.
func (c *Client) PeerAddr() net.Addr {
	if c.State() != StateConnected {
		return nil
	}
	return c.getPeerAddr()
}

// LastPeerAddr returns the last remote address.
func (c *Client) LastPeerAddr() net.Addr {
	return c.getPeerAddr()
}

// getPeerAddr returns the remote address.
func (c *Client) getPeerAddr() net.Addr {
	v := c.peerAddr.Load()
	if v == nil {
		return nil
	}
	h := v.(atomicAddr)
	return h.Addr
}

// GetAdapter returns the current network adapter.
func (c *Client) GetAdapter() common.TunnelAdapter {
	return c.adapter
}

// Events returns the channel for receiving client events.
func (c *Client) Events() <-chan *EventContext {
	return c.events
}

func (c *Client) drainQueues() {
	c.drainQueue(c.inbound)
	c.drainQueue(c.outbound.C)
}

func (c *Client) drainQueue(queue common.PacketQueue) {
	for {
		select {
		case pkt := <-queue:
			c.bufferPool.PutBuffer(pkt.Bytes())
		default:
			return
		}
	}
}

func (c *Client) resetClosed() {
	if c.closed.CompareAndSwap(true, false) {
		c.done = make(chan struct{})
	}
}
