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
	"runtime"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/transport"
)

// openStreams handles incoming stream connections from the QUIC transport.
func (c *Client) openStreams(ctx context.Context, conn transport.Conn) {
	streamCount := c.config.StreamCount
	if streamCount <= 0 {
		streamCount = runtime.NumCPU()
	}

	for i := 0; i < streamCount; i++ {
		stream, err := conn.NewStream(ctx)
		if err != nil {
			c.logger.Errorf("failed to create stream: %v", err)
			continue
		}
		stream.Flush()
		c.streams.Add(stream)
		c.mgrWg.Go(func() { c.doStream(ctx, stream) })
	}

	if c.streams.Count() == 0 {
		select {
		case c.connError <- fmt.Errorf("could not open streams"):
		default:
		}
		return
	}
}

func (c *Client) doStream(ctx context.Context, stream transport.Stream) {
	c.processInbound(ctx, stream)
	//defer func() {
	c.streams.Remove(stream)
	if c.streams.Count() == 0 {
		select {
		case c.connError <- fmt.Errorf("all streams closed"):
		default:
		}
		return
	}

	if common.IsContextDone(ctx) {
		return
	}

	c.mgrWg.Go(func() { c.reconnectStream(ctx, c.conn) })
	// // stream.Close()
	//}()
}

func (c *Client) reconnectStream(ctx context.Context, conn transport.Conn) {
	desiredCount := c.config.StreamCount
	if desiredCount <= 0 {
		desiredCount = runtime.NumCPU()
	}
	currentCount := c.streams.Count()

	if currentCount >= desiredCount {
		return
	}

	c.logger.Infof("reconnecting stream")

	stream, err := conn.NewStream(ctx)
	if err != nil {
		//conn.Close()
		c.logger.Errorf("failed to create stream: %v", err)
		return
	}

	c.streams.Add(stream)
	c.doStream(ctx, stream)
}
