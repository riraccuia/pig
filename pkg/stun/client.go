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

package stun

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// Client represents a STUN client with configurable settings.
type Client struct {
	Dialer         Dialer
	Timeout        time.Duration
	Logger         LoggerFunc
	Servers        []string
	BindingOptions BindingOptions
}

func (c *Client) dialer() Dialer {
	if c.Dialer != nil {
		return c.Dialer
	}
	return DefaultDialer
}

func (c *Client) logger() LoggerFunc {
	if c.Logger != nil {
		return c.Logger
	}
	return NoopLoggerFunc
}

func (c *Client) deadline(ctx context.Context, now time.Time) (earliest time.Time) {
	if c.Timeout != 0 { // including negative, for historical reasons
		earliest = now.Add(c.Timeout)
	}
	if d, ok := ctx.Deadline(); ok {
		earliest = minNonzeroTime(earliest, d)
	}
	if earliest.IsZero() {
		earliest = now.Add(stunTimeout)
	}
	return
}

func (c *Client) AddServer(serverAddr string) {
	c.Servers = append(c.Servers, serverAddr)
}

// WithLoggerFunc sets the logger function for the client.
func (c *Client) WithLoggerFunc(loggerFunc LoggerFunc) *Client {
	c.Logger = loggerFunc
	return c
}

// WithDialer sets the network dialer for the client to a custom one initiated by the caller.
func (c *Client) WithDialer(dialer Dialer) *Client {
	c.Dialer = dialer
	return c
}

// WithReceiveTimeout sets the receive timeout for the client receive operations.
func (c *Client) WithReceiveTimeout(receiveTimeout time.Duration) *Client {
	c.Timeout = receiveTimeout
	return c
}

// QueryServer performs a STUN query to the specified server and protocol.
// Valid protocols are "udp", "tcp" and "tls".
// It returns the binding result or an error if the query fails.
func (c *Client) QueryServer(ctx context.Context, stunServer string, sourcePort int, protocol string, tlsConfig *tls.Config) (*BindingResult, error) {
	switch protocol {
	case "udp":
		return QueryServerUDP(ctx, stunServer, &net.UDPAddr{IP: nil, Port: sourcePort})
	case "tcp":
		return QueryServerTCP(ctx, stunServer, &net.TCPAddr{IP: nil, Port: sourcePort})
	case "tls":
		if tlsConfig == nil {
			return nil, fmt.Errorf("TLS config is required for TLS queries")
		}
		return QueryServerTLS(ctx, stunServer, &net.TCPAddr{IP: nil, Port: sourcePort}, tlsConfig)
	default:
		return nil, fmt.Errorf("invalid protocol: %s", protocol)
	}
}

func (c *Client) QueryFromLocalAddr(ctx context.Context, localAddr net.Addr) (*BindingResult, error) {
	switch localAddr.Network() {
	case "udp":
		return c.QueryStunServerUDP(ctx, localAddr)
	case "tcp":
		return c.QueryStunServerTCP(ctx, localAddr)
	case "ip":
		localIP := localAddr.(*net.IPAddr).IP
		return c.QueryStunServerUDP(ctx, &net.UDPAddr{IP: localIP, Port: 0})
	default:
		return nil, fmt.Errorf("invalid network: %s", localAddr.Network())
	}
}

func (c *Client) resolveServerAddr(network string, localAddr net.Addr) (net.Addr, error) {
	for _, server := range c.Servers {
		var (
			addr net.Addr
			err  error
		)
		switch localAddr.(type) {
		case *net.UDPAddr:
			addr, err = net.ResolveUDPAddr(network, server)
		case *net.TCPAddr:
			addr, err = net.ResolveTCPAddr(network, server)
		default:
			continue
		}
		if err != nil {
			continue
		}
		return addr, nil
	}
	return nil, fmt.Errorf("no suitable server found for local address: %v", localAddr)
}

func minNonzeroTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.Before(b) {
		return a
	}
	return b
}
