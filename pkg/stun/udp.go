package stun

import (
	"fmt"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/common"
)

// QueryServerUDP is a convenience function that uses a StunClient under the hood.
func QueryServerUDP(logger common.Logger, stunServerAddr string, connOrSrcPort any) (mappedIP net.IP, mappedPort int, err error) {
	client := NewStunClient(logger, stunServerAddr)
	return client.QueryStunServerUDP(connOrSrcPort)
}

// QueryStunServerUDP takes a UDP connection or a source port and queries the STUN server.
func (c *StunClient) QueryStunServerUDP(connOrSrcPort any) (mappedIP net.IP, mappedPort int, err error) {
	conn, ok := connOrSrcPort.(*net.UDPConn)
	if ok {
		return c.queryStunServerUDP(conn)
	}
	srcPort, ok := connOrSrcPort.(int)
	if !ok {
		return nil, 0, fmt.Errorf("invalid source port: %v", connOrSrcPort)
	}
	return c.queryStunServerUDP(srcPort)
}

// QueryStunServerUDP sends a STUN Binding Request and returns the mapped IP and port.
// It uses the client's configured ServerAddr. connOrSrcPort is the UDP connection or the source port to send from.
func (c *StunClient) queryStunServerUDP(connOrSrcPort any) (mappedIP net.IP, mappedPort int, err error) {
	stunServerAddr := c.ServerAddr

	// Resolve server address
	serverAddr, err := net.ResolveUDPAddr("udp", stunServerAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to resolve STUN server address %s: %w", stunServerAddr, err)
	}

	// Create transaction ID and request
	txID, requestBytes, err := c.createStunRequest()
	if err != nil {
		return nil, 0, err
	}

	// Send request and receive response
	responseBytes, err := c.sendStunRequestUDP(serverAddr, connOrSrcPort, requestBytes, txID)
	if err != nil {
		return nil, 0, err
	}

	// Validate response header
	err = c.validateStunResponse(responseBytes, txID)
	if err != nil {
		return nil, 0, err
	}

	// Extract mapped address
	mappedIP, mappedPort, err = c.extractMappedAddress(responseBytes[20:])
	if err != nil {
		return nil, 0, err
	}

	if c.logger != nil {
		c.logger.Infof("STUN: Found mapped address %s:%d", mappedIP, mappedPort)
	}

	return mappedIP, mappedPort, nil
}

// sendStunRequestUDP sends a STUN UDP request and receives the response.
// connOrSrcPort is the UDP connection or the source port to send from.
func (c *StunClient) sendStunRequestUDP(serverAddr *net.UDPAddr, connOrSrcPort any, requestBytes []byte, txID [12]byte) (responseBytes []byte, err error) {
	udpConn, ok := connOrSrcPort.(*net.UDPConn)
	if !ok {
		srcPort, ok := connOrSrcPort.(int)
		if !ok {
			return nil, fmt.Errorf("invalid source port: %v", connOrSrcPort)
		}
		laddr := &net.UDPAddr{
			IP:   net.IPv4zero, // Listen on all available IPs
			Port: srcPort,
		}
		udpConn, err = net.ListenUDP("udp4", laddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on UDP port %d: %w", srcPort, err)
		}
		// only close the connection if we created it
		defer udpConn.Close()
	}

	srcPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	if c.logger != nil {
		c.logger.Infof("STUN: Sending Binding Request from :%d to %s (TX ID: %x)", srcPort, serverAddr, txID[:4])
	}

	// Send request
	_, err = udpConn.WriteToUDP(requestBytes, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to send STUN request: %w", err)
	}

	// Receive response with timeout
	responseBytes = make([]byte, 1500) // MTU size buffer
	udpConn.SetReadDeadline(time.Now().Add(stunTimeout))
	defer udpConn.SetReadDeadline(time.Time{})
	n, remoteAddr, err := udpConn.ReadFromUDP(responseBytes)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("STUN request timed out")
		}
		return nil, fmt.Errorf("failed to read STUN response: %w", err)
	}

	// Trim buffer to actual received size
	responseBytes = responseBytes[:n]

	if c.logger != nil {
		c.logger.Debugf("STUN: Received %d bytes response from %s", n, remoteAddr)
	}

	return responseBytes, nil
}
