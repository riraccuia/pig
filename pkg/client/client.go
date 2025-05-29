package client

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/packet"
	"github.com/riraccuia/pig/pkg/queue"
	"github.com/riraccuia/pig/pkg/queue/wred"
	"github.com/riraccuia/pig/pkg/script"
	"github.com/riraccuia/pig/pkg/streams"
	"github.com/riraccuia/pig/pkg/transport"
)

// Client represents a tunnel client that handles traffic between
// a local network adapter and a remote server.
type Client struct {
	logger            common.Logger
	dropLogger        *common.DelayedCounterProcessor
	config            *config.Config
	conn              transport.Conn
	streams           *streams.StreamManager
	adapter           common.TunnelAdapter
	inbound           common.PacketQueue
	outbound          *queue.ChanQueue //common.PacketQueue
	bufferPool        *sync.Pool
	stopFunc          func()
	done              chan struct{}
	closed            atomic.Bool
	reconnectInterval time.Duration
	connError         chan error
	scriptExecutor    *script.Executor
	authenticator     common.Authenticator
}

// New creates a new Client instance with the default network adapter.
func New(logger common.Logger, cfg *config.Config, authenticator common.Authenticator) (*Client, error) {
	adapter, err := getAdapter(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create adapter: %w", err)
	}
	return NewWithAdapter(logger, cfg, adapter, authenticator)
}

// NewWithAdapter creates a new Client instance with a custom network adapter.
func NewWithAdapter(logger common.Logger, cfg *config.Config, adapter common.TunnelAdapter, authenticator common.Authenticator) (*Client, error) {
	logger.Infof("Creating client with adapter %s, IP: %s, MTU %d", adapter.Name(), adapter.IP(), cfg.MTU)

	if cfg.QueueSize <= 0 {
		cfg.QueueSize = common.DefaultQueueSize
	}

	outbound := queue.NewChanQueue(cfg.QueueSize)
	if cfg.Wred.DropProbability > 0 {
		wred, err := wred.NewWRED(cfg.Wred.WeightFactor)
		if err != nil {
			return nil, fmt.Errorf("failed to create WRED: %w", err)
		}
		logger.Infof("WRED enabled with weight factor: %d, drop probability: %d%%, threshold avg queue len: %d%%", int(cfg.Wred.WeightFactor), int(cfg.Wred.DropProbability*100), int(cfg.Wred.Threshold*100))
		outbound = outbound.WithWRED(wred, cfg.Wred.DropProbability, cfg.Wred.Threshold)
	}

	return &Client{
		logger:   logger,
		config:   cfg,
		streams:  streams.New(),
		adapter:  adapter,
		inbound:  make(common.PacketQueue, cfg.QueueSize),
		outbound: outbound,
		bufferPool: &sync.Pool{
			New: func() interface{} {
				return make(packet.IPv4Packet, cfg.MTU, cfg.MTU)
			},
		},
		done:              make(chan struct{}),
		reconnectInterval: time.Duration(cfg.ReconnectInterval) * time.Second,
		connError:         make(chan error, 1),
		scriptExecutor:    script.New(logger, cfg.StartScript, cfg.StopScript),
		authenticator:     authenticator,
	}, nil
}

// Start initializes the client connection and starts all necessary goroutines
// for handling traffic. The dialFunc parameter provides the connection to the server.
func (c *Client) Start(ctx context.Context, dialFunc func() (transport.Conn, error)) error {
	c.logger.Infof("Starting client with reconnect interval %d seconds", c.reconnectInterval/time.Second)
	c.dropLogger = common.NewDelayedCounterProcessor(func(c1, c2 *atomic.Uint64) {
		c.logger.Infof("Dropped %d packets (%d bytes)", c1.Load(), c2.Load())
	}).WithBackoff(time.Second, time.Second*15)
	c.dropLogger.Start(ctx)
	go c.readFromAdapter(ctx)
	go c.writeToAdapter(ctx)
	go c.manageConnection(ctx, dialFunc)
	return nil
}

func (c *Client) manageConnection(ctx context.Context, dialFunc func() (transport.Conn, error)) {
	for {
		c.logger.Infof("Connecting to server...")
		conn, err := dialFunc()
		if err != nil {
			select {
			case <-ctx.Done():
				c.logger.Infof("Context done, exiting")
				return
			case <-time.After(c.reconnectInterval):
				c.logger.Errorf("Connection failed, retrying: %v", err)
				continue
			}
		}

		// Perform authentication if configured
		if c.authenticator != nil {
			if err := c.authenticator.Authenticate(ctx, conn); err != nil {
				c.logger.Errorf("Failed to authenticate: %v", err)
				conn.Close()
				continue
			}
		}

		c.drainQueues()
		c.conn = conn
		c.resetClosed()

		go c.handleInbound(ctx)
		go c.handleOutbound(ctx)

		c.logger.Infof("Connected to server %s", conn.RemoteAddr())

		// Execute start script
		c.scriptExecutor.ExecuteStartScript(script.ScriptContext{
			TunnelName:  c.adapter.Name(),
			TunnelIndex: c.adapter.Index(),
			RemoteAddr:  strings.Split(conn.RemoteAddr().String(), ":")[0],
			NatAddr:     "", // No NAT address in client mode
			TunnelProto: string(c.config.Proto),
		})

		c.stopFunc = func() {
			c.logger.Debug("Executing stop script")
			c.scriptExecutor.ExecuteStopScript(script.ScriptContext{
				TunnelName:  c.adapter.Name(),
				TunnelIndex: c.adapter.Index(),
				RemoteAddr:  strings.Split(conn.RemoteAddr().String(), ":")[0],
				NatAddr:     "", // No NAT address in client mode
				TunnelProto: string(c.config.Proto),
			})
		}

		select {
		case <-c.done:
			c.logger.Infof("Client stopped")
			return
		case <-ctx.Done():
			c.logger.Infof("Context done, exiting")
			c.Close()
			return
		case err := <-c.connError:
			c.logger.Errorf("Connection lost: %v", err)
			c.Close()
			<-time.After(c.reconnectInterval)
			continue
		}
	}
}

// Close gracefully shuts down the client and all its goroutines
func (c *Client) Close() error {
	if c.closed.CompareAndSwap(false, true) {
		close(c.done)
		c.streams.CloseAll()
		if c.conn != nil {
			c.conn.Close()
		}
		if c.stopFunc != nil {
			c.stopFunc()
		}
	}
	return nil
}

// GetAdapter returns the current network adapter
func (c *Client) GetAdapter() common.TunnelAdapter {
	return c.adapter
}

// Wait blocks until the client is done
func (c *Client) Wait() {
	<-c.done
}

func (c *Client) drainQueues() {
	c.drainQueue(c.inbound)
	c.drainQueue(c.outbound.C)
}

func (c *Client) drainQueue(queue common.PacketQueue) {
	for {
		select {
		case pkt := <-queue:
			c.bufferPool.Put(pkt)
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
