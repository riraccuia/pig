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
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// Client represents a STUN client with configurable settings.
type Client struct {
	logger         LoggerFunc
	dialer         *net.Dialer
	receiveTimeout time.Duration
	ServerAddr     string
	bindingOptions *BindingOptions
}

// NewClient creates a new STUN client instance. As a default, it will require a fingerprint in the response.
// Use WithBindingOptions() to customize the binding options.
func NewClient(serverAddr string) *Client {
	return &Client{
		logger:         func(level string, args ...any) {},
		dialer:         &net.Dialer{},
		receiveTimeout: stunTimeout,
		ServerAddr:     serverAddr,
		bindingOptions: &BindingOptions{},
	}
}

// WithLoggerFunc sets the logger function for the client.
func (c *Client) WithLoggerFunc(loggerFunc LoggerFunc) *Client {
	c.logger = loggerFunc
	return c
}

// WithBindingOptions sets the binding options for the client.
func (c *Client) WithBindingOptions(bindingOptions *BindingOptions) *Client {
	if bindingOptions == nil {
		bindingOptions = &BindingOptions{}
	}
	c.bindingOptions = bindingOptions
	return c
}

// WithDialer sets the network dialer for the client to a custom one initiated by the caller.
func (c *Client) WithDialer(dialer *net.Dialer) *Client {
	c.dialer = dialer
	return c
}

// WithReceiveTimeout sets the receive timeout for the client receive operations.
func (c *Client) WithReceiveTimeout(receiveTimeout time.Duration) *Client {
	c.receiveTimeout = receiveTimeout
	return c
}

// QueryServer performs a STUN query to the specified server and protocol.
// Valid protocols are "udp", "tcp" and "tls".
// It returns the binding result or an error if the query fails.
func (c *Client) QueryServer(stunServer string, sourcePort int, protocol string, tlsConfig *tls.Config) (*BindingResult, error) {
	switch protocol {
	case "udp":
		return QueryServerUDP(stunServer, &net.UDPAddr{IP: nil, Port: sourcePort})
	case "tcp":
		return QueryServerTCP(stunServer, &net.TCPAddr{IP: nil, Port: sourcePort})
	case "tls":
		if tlsConfig == nil {
			return nil, fmt.Errorf("TLS config is required for TLS queries")
		}
		return QueryServerTLS(stunServer, &net.TCPAddr{IP: nil, Port: sourcePort}, tlsConfig)
	default:
		return nil, fmt.Errorf("invalid protocol: %s", protocol)
	}
}

// sendStunRequestConn sends a STUN TCP request and receives the response.
// conn is the TCP or TLS connection to send from.
func (c *Client) sendStunRequestConn(serverAddr *net.TCPAddr, conn net.Conn, request *Message, txID [12]byte) (response *Message, err error) {
	srcPort := conn.LocalAddr().(*net.TCPAddr).Port

	if c.logger != nil {
		c.logger("info", fmt.Sprintf("STUN: Sending Binding Request over %s from :%d to %s (TX ID: %x)",
			conn.LocalAddr().Network(), srcPort, serverAddr, txID[:4]))
	}

	// Set timeouts
	conn.SetDeadline(time.Now().Add(c.receiveTimeout))
	defer conn.SetDeadline(time.Time{})

	// Send request
	_, err = request.WriteTo(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to send STUN request over TCP: %w", err)
	}

	// Receive response - read the full 20-byte header first
	responseHeader := make([]byte, 20)
	_, err = io.ReadFull(conn, responseHeader)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("STUN TCP request timed out")
		}
		return nil, fmt.Errorf("failed to read STUN response header: %w", err)
	}

	// Parse the length from the header to determine how many more bytes to read
	messageLength := int(binary.BigEndian.Uint16(responseHeader[2:4]))

	// Allocate buffer for the complete message (header + attributes)
	responseBytes := make([]byte, 20+messageLength)
	copy(responseBytes, responseHeader)

	// Read the rest of the message if there are attributes
	if messageLength > 0 {
		_, err = io.ReadFull(conn, responseBytes[20:20+messageLength])
		if err != nil {
			return nil, fmt.Errorf("failed to read STUN response attributes: %w", err)
		}
	}

	c.logger("debug", fmt.Sprintf("STUN: Received %d bytes response over TCP from %s", len(responseBytes), serverAddr))

	return DecodeMessage(responseBytes)
}
