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
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"
)

// QueryServerTCP is a convenience function that queries a STUN server over TCP.
// It discovers the IP address and port as seen from the public internet.
func QueryServerTCP(ctx context.Context, stunServerAddr string, connOrLocalAddr any) (*BindingResult, error) {
	client := &Client{}
	client.AddServer(stunServerAddr)
	return client.QueryStunServerTCP(ctx, connOrLocalAddr)
}

// QueryStunServerTCP takes a TCP connection or a source port and queries the STUN server over TCP.
// This method discovers your public IP address and port as seen from the internet.
// It accepts either an existing TCP connection (*net.TCPConn) or a local address (*net.TCPAddr).
// If a source port is provided, a new TCP connection will be established and closed after the query.
func (c *Client) QueryStunServerTCP(ctx context.Context, connOrLocalAddr any) (*BindingResult, error) {
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
		return c.queryStunServerTCP(ctx, serverAddr.(*net.TCPAddr), conn)
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
	return c.queryStunServerTCP(ctx, serverAddr.(*net.TCPAddr), localAddr)
}

// queryStunServerTCP sends a STUN Binding Request over TCP and returns the mapped IP and port.
// It uses the client's configured ServerAddr. connOrLocalAddr is the TCP connection or the local address to send from.
func (c *Client) queryStunServerTCP(ctx context.Context, serverAddr *net.TCPAddr, connOrLocalAddr any) (*BindingResult, error) {
	request, err := BuildBindingRequest(&c.BindingOptions)
	if err != nil {
		return nil, err
	}

	// Send request and receive response
	response, err := c.sendStunRequestTCP(ctx, serverAddr, connOrLocalAddr, request, request.Header.TransactionID)
	if err != nil {
		return nil, err
	}

	result, err := ProcessBindingResponse(response, request.Header.TransactionID, &c.BindingOptions)
	result.ServerAddr = serverAddr.String()
	return result, err
}

// sendStunRequestTCP sends a STUN TCP request and receives the response.
// connOrLocalAddr is the TCP connection or the local address to send from.
func (c *Client) sendStunRequestTCP(ctx context.Context, serverAddr *net.TCPAddr, connOrLocalAddr any, request *Message, txID [12]byte) (response *Message, err error) {
	var tcpConn *net.TCPConn
	// Check if we received an existing connection or need to create one
	tcpConn, ok := connOrLocalAddr.(*net.TCPConn)
	if !ok {
		laddr, ok := connOrLocalAddr.(*net.TCPAddr)
		if !ok {
			return nil, fmt.Errorf("invalid local address: %v", connOrLocalAddr)
		}
		// Create a new TCP connection
		tcpConn, err = c.createTCPConnection(serverAddr, laddr)
		if err != nil {
			return nil, err
		}
		// Only close the connection if we created it
		defer tcpConn.Close()
	}
	return c.sendStunRequestConn(ctx, serverAddr, tcpConn, request, txID)
}

// createTCPConnection creates a TCP connection to the STUN server from the specified local port.
func (c *Client) createTCPConnection(serverAddr *net.TCPAddr, laddr *net.TCPAddr) (*net.TCPConn, error) {
	if laddr.IP == nil {
		// if the local address is nil, use the zero address
		// buf first we have to check if the server address is IPv4 or IPv6
		laddr.IP = net.IPv4zero
		if serverAddr.IP != nil && serverAddr.IP.To4() == nil {
			laddr.IP = net.IPv6zero
		}
	}
	dialLaddr, ok := netip.AddrFromSlice(laddr.IP)
	if !ok {
		return nil, fmt.Errorf("failed to convert local address to netip.Addr")
	}
	if serverAddr.IP == nil {
		serverAddr.IP = net.IPv4zero
		if laddr.IP.To4() == nil {
			serverAddr.IP = net.IPv6zero
		}
	}
	dialRaddr, ok := netip.AddrFromSlice(serverAddr.IP)
	if !ok {
		return nil, fmt.Errorf("failed to convert server address to netip.Addr")
	}
	conn, err := c.dialer().DialTCP(context.Background(), "tcp", netip.AddrPortFrom(dialLaddr, uint16(laddr.Port)), netip.AddrPortFrom(dialRaddr, uint16(serverAddr.Port)))
	if err != nil {
		return nil, fmt.Errorf("failed to connect to STUN server %s from %s: %w", serverAddr, laddr, err)
	}
	return conn, nil
}

// sendStunRequestConn sends a STUN TCP request and receives the response.
// conn is the TCP or TLS connection to send from.
func (c *Client) sendStunRequestConn(ctx context.Context, serverAddr *net.TCPAddr, conn net.Conn, request *Message, txID [12]byte) (response *Message, err error) {
	srcPort := conn.LocalAddr().(*net.TCPAddr).Port

	c.logger()("info", fmt.Sprintf("STUN: Sending Binding Request over %s from :%d to %s (TX ID: %x)",
		conn.LocalAddr().Network(), srcPort, serverAddr, txID[:4]))

	// Set timeouts
	conn.SetDeadline(c.deadline(ctx, time.Now()))
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

	c.logger()("trace", fmt.Sprintf("STUN: Received %d bytes response over TCP from %s", len(responseBytes), serverAddr))

	return DecodeMessage(responseBytes)
}
