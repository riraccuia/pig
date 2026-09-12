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
	"fmt"
	"net"
	"net/netip"
	"time"
)

// QueryServerUDP is a convenience function that queries a STUN server over UDP.
// It discovers the IP address and port as seen from the public internet.
func QueryServerUDP(stunServerAddr string, connOrLocalAddr any) (*BindingResult, error) {
	client := NewClient(stunServerAddr)
	return client.QueryStunServerUDP(connOrLocalAddr)
}

// QueryStunServerUDP takes a UDP connection or a source port and queries the STUN server over UDP.
// This method discovers your public IP address and port as seen from the internet.
// It accepts either an existing UDP connection (*net.UDPConn) or a local address (*net.UDPAddr).
// If a source port is provided, a new UDP connection will be established and closed after the query.
func (c *Client) QueryStunServerUDP(connOrLocalAddr any) (*BindingResult, error) {
	conn, ok := connOrLocalAddr.(*net.UDPConn)
	if ok {
		network := "udp4"
		if conn.LocalAddr().(*net.UDPAddr).IP.To4() == nil {
			network = "udp6"
		}
		serverAddr, err := net.ResolveUDPAddr(network, c.ServerAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve STUN server address (%s) %s: %w", network, c.ServerAddr, err)
		}
		return c.queryStunServerUDP(serverAddr, conn)
	}
	localAddr, ok := connOrLocalAddr.(*net.UDPAddr)
	if !ok {
		return nil, fmt.Errorf("invalid local address: %v", connOrLocalAddr)
	}
	var network string
	switch {
	case localAddr.IP == nil:
		network = "udp"
	case localAddr.IP.To4() == nil:
		network = "udp6"
	default:
		network = "udp4"
	}
	serverAddr, err := net.ResolveUDPAddr(network, c.ServerAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve STUN server address (%s) %s: %w", network, c.ServerAddr, err)
	}
	return c.queryStunServerUDP(serverAddr, localAddr)
}

// QueryStunServerUDP sends a STUN Binding Request and returns the mapped IP and port.
// It uses the client's configured ServerAddr. connOrLocalAddr is the UDP connection or the local address to send from.
func (c *Client) queryStunServerUDP(serverAddr *net.UDPAddr, connOrLocalAddr any) (*BindingResult, error) {
	request, err := BuildBindingRequest(c.bindingOptions)
	if err != nil {
		return nil, err
	}

	// Send request and receive response
	response, err := c.sendStunRequestUDP(serverAddr, connOrLocalAddr, request, request.Header.TransactionID)
	if err != nil {
		return nil, err
	}

	result, err := ProcessBindingResponse(response, request.Header.TransactionID, c.bindingOptions)
	result.ServerAddr = serverAddr.String()
	return result, err
}

// sendStunRequestUDP sends a STUN UDP request and receives the response.
// connOrSrcPort is the UDP connection or the source port to send from.
func (c *Client) sendStunRequestUDP(serverAddr *net.UDPAddr, connOrLocalAddr any, request *Message, txID [12]byte) (response *Message, err error) {
	udpConn, ok := connOrLocalAddr.(net.Conn)
	if !ok {
		laddr, ok := connOrLocalAddr.(*net.UDPAddr)
		if !ok {
			return nil, fmt.Errorf("invalid local address: %v", connOrLocalAddr)
		}
		udpConn, err = c.createUDPConnection(serverAddr, laddr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial UDP: %w", err)
		}
		// only close the connection if we created it
		defer udpConn.Close()
	}

	srcPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	c.logger("info", fmt.Sprintf("STUN: Sending Binding Request over UDP from :%d to %s (TX ID: %x)", srcPort, serverAddr, txID[:4]))

	// Send request
	_, err = request.WriteTo(udpConn)
	if err != nil {
		return nil, fmt.Errorf("failed to send STUN request over UDP: %w", err)
	}

	// Receive response with timeout
	responseBytes := make([]byte, 1500) // MTU size buffer
	udpConn.SetReadDeadline(time.Now().Add(c.receiveTimeout))
	defer udpConn.SetReadDeadline(time.Time{})
	n, err := udpConn.Read(responseBytes)
	//n, remoteAddr, err := udpConn.ReadFromUDP(responseBytes)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("STUN UDP request timed out")
		}
		return nil, fmt.Errorf("failed to read STUN response: %w", err)
	}

	// Trim buffer to actual received size
	responseBytes = responseBytes[:n]

	c.logger("debug", fmt.Sprintf("STUN: Received %d bytes response over UDP from %s", n, serverAddr))

	return DecodeMessage(responseBytes)
}

func (c *Client) createUDPConnection(serverAddr *net.UDPAddr, laddr *net.UDPAddr) (*net.UDPConn, error) {
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
		return nil, fmt.Errorf("failed to convert server address %s to netip.Addr", serverAddr.IP)
	}
	return c.dialer.DialUDP(context.Background(), "udp", netip.AddrPortFrom(dialLaddr, uint16(laddr.Port)), netip.AddrPortFrom(dialRaddr, uint16(serverAddr.Port)))
}
