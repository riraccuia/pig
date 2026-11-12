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
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/queue"
	"github.com/riraccuia/pig/pkg/streams"
	"github.com/riraccuia/pig/pkg/transport"
)

// Client represents a tunnel client that handles traffic between
// a local network adapter and a remote server.
type Client struct {
	logger               common.Logger
	dropLogger           *common.DelayedCounterProcessor
	config               *config.TunnelConfig
	adapterConfig        *config.AdapterConfig
	conn                 transport.Conn
	streams              *streams.StreamManager
	adapter              common.TunnelAdapter
	inbound              common.PacketQueue
	outbound             *queue.FIFO[network.IPPacket]
	bufferPool           common.BufferPool
	authenticator        common.Authenticator
	state                atomic.Int32
	peerAddr             atomic.Value
	conntrack            *Conntrack
	started, closed      atomic.Bool
	mainWg, mgrWg, outWg sync.WaitGroup
	connError            chan error
	events               chan *EventContext
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
	logger.Infof("New client with adapter %s, IP: %s, MTU %d", adapter.Name(), adapter.IP(), adapter.MTU())

	adapterConfig := adapterCfg
	if tunnelCfg.Adapter != nil {
		adapterConfig = tunnelCfg.Adapter
	}

	cl := &Client{
		logger:        logger,
		config:        tunnelCfg,
		streams:       streams.New(),
		adapter:       adapter,
		bufferPool:    common.DefaultBufferPool,
		adapterConfig: adapterConfig,
		connError:     make(chan error, 1),
		authenticator: authenticator,
		events:        make(chan *EventContext, 10),
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
	if !c.started.CompareAndSwap(false, true) {
		return nil
	}

	select {
	case <-ctx.Done():
		c.started.Store(false)
		return ctx.Err()
	default:
	}

	if c.dropLogger == nil {
		c.dropLogger = common.NewDelayedCounterProcessor(func(c1, c2 *atomic.Uint64) {
			c.logger.Infof("Dropped %d packets (%d bytes)", c1.Load(), c2.Load())
		}).WithBackoff(time.Second, time.Second*15)
		c.dropLogger.Start(ctx)
	}

	c.mainWg.Go(func() {
		c.manageConnection(ctx, dialFunc)
		c.started.Store(false)
	})

	return nil
}

func (c *Client) manageConnection(ctx context.Context, dialFunc func(ctx context.Context) (transport.Conn, error)) {
	c.logger.Info("Connecting")

	ctx, cancel := context.WithCancel(ctx)

	c.drainConnError()

	c.conntrack = NewConntrack(ctx)
	c.setupQueues()

	if deadliner, ok := c.adapter.(transport.DeadLiner); ok {
		// cancel any previous deadline
		deadliner.SetReadDeadline(time.Time{})
	}

	conn, err := dialFunc(ctx)
	if err != nil {
		c.logger.Errorf("Failed to connect: %v", err)
		if common.IsContextDone(ctx) {
			event := &EventContext{State: StateStopped}
			c.cancelAndSignalEvent(cancel, event)
			c.logger.Info("Context done, exiting")
			return
		}
		event := &EventContext{State: StateConnectionFailed, Error: err}
		c.cancelAndSignalEvent(cancel, event)
		return
	}

	// Perform authentication if configured
	if c.authenticator != nil {
		c.logger.Infof("Authenticating connection to %s", conn.RemoteAddr())
		if err := c.authenticator.Authenticate(ctx, conn); err != nil {
			c.logger.Errorf("Failed to authenticate: %v", err)
			event := &EventContext{State: StateConnectionFailed, Error: err}
			c.cancelAndSignalEvent(cancel, event)
			return
		}
	}

	c.conn = conn

	c.resetClosed()

	c.mgrWg.Go(func() { c.readFromAdapter(ctx) })
	c.mgrWg.Go(func() { c.writeToAdapter() })
	c.mgrWg.Go(func() { c.handleInbound(ctx, conn) })
	c.outWg.Go(func() { c.handleOutbound(conn) })

	c.logger.Infof("Connected: %s", conn.RemoteAddr())
	c.signalEvent(&EventContext{State: StateConnected, Conn: conn})

	select {
	case <-ctx.Done():
		c.logger.Info("Context done, exiting")
		event := &EventContext{State: StateStopped, Conn: c.conn, Error: ctx.Err()}
		c.cancelAndSignalEvent(cancel, event)
	case err := <-c.connError:
		c.logger.Errorf("Connection lost: %v", err)
		event := &EventContext{State: StateDisconnected, Conn: c.conn, Error: err}
		c.cancelAndSignalEvent(cancel, event)
	}

	c.mgrWg.Wait()
}

func (c *Client) Name() string {
	return c.config.Name
}

// Config returns the tunnel configuration.
func (c *Client) Config() *config.TunnelConfig { return c.config }

// Wait waits for the client tunnel to stop.
func (c *Client) Wait() {
	c.mainWg.Wait()
}

// cancelAndSignalEvent signals the given event, then gracefully clears state and connections
// for this client so it can be reused.
func (c *Client) cancelAndSignalEvent(cancel context.CancelFunc, event *EventContext) {
	if !c.closed.CompareAndSwap(false, true) {
		return
	}
	// stop producing outbound packets
	if dl, ok := c.adapter.(transport.DeadLiner); ok {
		dl.SetReadDeadline(time.Now())
	}
	// close the outbound queue and wait for the last
	// packets to be processed
	c.outbound.Close()
	c.outWg.Wait()
	// close all streams (if any) and the connection
	c.streams.CloseAll()
	if c.conn != nil {
		_ = c.conn.Close()
	}
	// cancel the context
	cancel()
	// close the inbound queue
	close(c.inbound)
	// signal the event
	if event != nil {
		c.signalEvent(event)
	}
	// set the state to stopped and drain the queues from any leftover packets
	c.state.Store(int32(StateStopped))
	c.drainQueues()
}

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
	queue.DrainQueue(c.inbound, func(pkt network.IPPacket) {
		c.bufferPool.PutBuffer(pkt.Bytes())
	})
	queue.DrainQueue(c.outbound, func(pkt network.IPPacket) {
		c.bufferPool.PutBuffer(pkt.Bytes())
	})
}

func (c *Client) drainConnError() {
	select {
	case <-c.connError:
	default:
	}
}

func (c *Client) setupQueues() {
	queueSize := c.adapterConfig.QueueSize
	if queueSize <= 0 {
		queueSize = config.DefaultQueueSize
	}

	c.outbound = queue.NewFIFO[network.IPPacket](queueSize)
	if c.config.Wred.MaxDropProbability > 0 {
		c.outbound = c.outbound.WithWRED(c.config.Wred.WeightFactor, c.config.Wred.MaxDropProbability, c.config.Wred.MinThreshold, c.config.Wred.MaxThreshold)
		c.logger.Infof("WRED on | Weight-Factor: %d | Max-Drop-Probability: %d%% | Queue-Threshold: min %d%%, max %d%%",
			int(c.config.Wred.WeightFactor),
			int(c.config.Wred.MaxDropProbability*100),
			int(c.config.Wred.MinThreshold*100),
			int(c.config.Wred.MaxThreshold*100))
	}

	c.inbound = make(common.PacketQueue, queueSize)
}

func (c *Client) resetClosed() {
	c.closed.CompareAndSwap(true, false)
}

func (c *Client) blockSize() int {
	return c.adapter.BlockSize()
}
