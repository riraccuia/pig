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
)

// QueryServerTLS is a convenience function that queries a STUN server over TLS.
// It discovers the IP address and port as seen from the public internet.
func QueryServerTLS(ctx context.Context, stunServerAddr string, connOrLocalAddr any, tlsConfig *tls.Config) (*BindingResult, error) {
	client := &Client{}
	client.AddServer(stunServerAddr)
	return client.QueryStunServerTLS(ctx, connOrLocalAddr, tlsConfig)
}

// QueryStunServerTLS takes a TLS connection or a source port and queries the STUN server over TLS.
// This method discovers your public IP address and port as seen from the internet.
// It accepts either an existing TLS connection (*net.TCPConn) or a local address (*net.TCPAddr).
// If a source port is provided, a new TLS connection will be established and closed after the query.
func (c *Client) QueryStunServerTLS(ctx context.Context, connOrLocalAddr any, tlsConfig *tls.Config) (*BindingResult, error) {
	conn, ok := connOrLocalAddr.(*net.TCPConn)
	if ok {
		network := "tcp4"
		if conn.LocalAddr().(*net.TCPAddr).IP.To4() == nil {
			network = "tcp6"
		}
		serverAddr, err := c.resolveServerAddr(network, conn.LocalAddr())
		if err != nil {
			return nil, fmt.Errorf("failed to resolve STUN server address (%s) %s: %w", network, c.Servers, err)
		}
		return c.queryStunServerTLS(ctx, serverAddr.(*net.TCPAddr), conn, tlsConfig)
	}
	localAddr, ok := connOrLocalAddr.(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("invalid local address: %v", connOrLocalAddr)
	}
	var network string
	switch {
	case localAddr.IP == nil:
		network = "tcp"
	case localAddr.IP.To4() == nil:
		network = "tcp6"
	default:
		network = "tcp4"
	}
	serverAddr, err := c.resolveServerAddr(network, localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve STUN server address (%s) %s: %w", network, c.Servers, err)
	}
	return c.queryStunServerTLS(ctx, serverAddr.(*net.TCPAddr), localAddr, tlsConfig)
}

// queryStunServerTLS sends a STUN Binding Request over TLS and returns the mapped IP and port.
// It uses the client's configured ServerAddr. connOrLocalAddr is the TLS connection or the local address to send from.
func (c *Client) queryStunServerTLS(ctx context.Context, serverAddr *net.TCPAddr, connOrLocalAddr any, tlsConfig *tls.Config) (*BindingResult, error) {
	request, err := BuildBindingRequest(&c.BindingOptions)
	if err != nil {
		return nil, err
	}

	// Send request and receive response
	response, err := c.sendStunRequestTLS(ctx, serverAddr, connOrLocalAddr, request, request.Header.TransactionID, tlsConfig)
	if err != nil {
		return nil, err
	}

	result, err := ProcessBindingResponse(response, request.Header.TransactionID, &c.BindingOptions)
	result.ServerAddr = serverAddr.String()
	return result, err
}

// sendStunRequestTLS sends a STUN TLS request and receives the response.
// connOrLocalAddr is the TLS connection or the local address to send from.
func (c *Client) sendStunRequestTLS(ctx context.Context, serverAddr *net.TCPAddr, connOrLocalAddr any, request *Message, txID [12]byte, tlsConfig *tls.Config) (response *Message, err error) {
	var tlsConn *tls.Conn
	// Check if we received an existing connection or need to create one
	tlsConn, ok := connOrLocalAddr.(*tls.Conn)
	if !ok {
		laddr, ok := connOrLocalAddr.(*net.TCPAddr)
		if !ok {
			return nil, fmt.Errorf("invalid source port: %v", connOrLocalAddr)
		}
		// Create a new TLS connection
		tlsConn, err = c.createTLSConnection(serverAddr, laddr, tlsConfig)
		if err != nil {
			return nil, err
		}
		// Only close the connection if we created it
		defer tlsConn.Close()
	}
	return c.sendStunRequestConn(ctx, serverAddr, tlsConn, request, txID)
}

// createTLSConnection creates a TLS connection to the STUN server from the specified local port.
func (c *Client) createTLSConnection(serverAddr *net.TCPAddr, laddr *net.TCPAddr, tlsConfig *tls.Config) (*tls.Conn, error) {
	tcpConn, err := c.createTCPConnection(serverAddr, laddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS connection: %w", err)
	}
	tlsConn := tls.Client(tcpConn, tlsConfig)
	return tlsConn, nil
}
