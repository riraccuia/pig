package client

import (
	"context"
	"fmt"
	"runtime"

	"github.com/riraccuia/pig/pkg/transport"
)

// openStreams handles incoming stream connections from the QUIC transport
func (c *Client) openStreams(ctx context.Context) {
	streamCount := c.config.StreamCount
	if streamCount <= 0 {
		streamCount = runtime.NumCPU()
	}

	for i := 0; i < streamCount; i++ {
		stream, err := c.conn.NewStream(ctx)
		if err != nil {
			c.logger.Errorf("failed to create stream: %v", err)
			return
		}
		stream.Flush()
		c.streams.Add(stream)
		go c.doStream(ctx, stream)
	}
}

func (c *Client) doStream(ctx context.Context, stream transport.Stream) {
	defer func() {
		c.removeStream(stream)
		if c.streams.Count() == 0 {
			select {
			case c.connError <- fmt.Errorf("all streams closed"):
			default:
			}
			return
		}
		if c.conn == nil {
			return
		}
		go c.reconnectStream(ctx)
		// stream.Close()
	}()
	c.processInbound(stream)
}

// removeStream removes a stream from the stream manager
func (c *Client) removeStream(stream transport.Stream) {
	c.streams.Remove(stream)
}

func (c *Client) reconnectStream(ctx context.Context) {
	desiredCount := c.config.StreamCount
	if desiredCount <= 0 {
		desiredCount = 5
	}
	currentCount := c.streams.Count()

	if currentCount >= desiredCount {
		return
	}

	c.logger.Infof("reconnecting stream")

	stream, err := c.conn.NewStream(ctx)
	if err != nil {
		c.conn.Close()
		c.logger.Errorf("failed to create stream: %v", err)
		return
	}

	c.streams.Add(stream)
	go c.doStream(ctx, stream)
}
