package stun

import (
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/ice/conn"
)

// QueryServerTCP is a convenience function that queries a STUN server over TCP.
// It discovers the IP address and port as seen from the public internet.
func QueryServerTCP(logger common.Logger, stunServerAddr string, connOrSrcPort any) (mappedIP net.IP, mappedPort int, err error) {
	client := NewStunClient(logger, stunServerAddr, nil)
	return client.QueryStunServerTCP(connOrSrcPort)
}

// QueryStunServerTCP takes a TCP connection or a source port and queries the STUN server over TCP.
// This method discovers your public IP address and port as seen from the internet.
// It accepts either an existing TCP connection (*net.TCPConn) or a source port number (int).
// If a source port is provided, a new TCP connection will be established and closed after the query.
func (c *StunClient) QueryStunServerTCP(connOrSrcPort any) (mappedIP net.IP, mappedPort int, err error) {
	conn, ok := connOrSrcPort.(*net.TCPConn)
	if ok {
		c.ServerAddr = conn.RemoteAddr().String()
		return c.queryStunServerTCP(conn)
	}
	srcPort, ok := connOrSrcPort.(int)
	if !ok {
		return nil, 0, fmt.Errorf("invalid source port: %v", connOrSrcPort)
	}
	return c.queryStunServerTCP(srcPort)
}

// queryStunServerTCP sends a STUN Binding Request over TCP and returns the mapped IP and port.
// It uses the client's configured ServerAddr. connOrSrcPort is the TCP connection or the source port to send from.
func (c *StunClient) queryStunServerTCP(connOrSrcPort any) (mappedIP net.IP, mappedPort int, err error) {
	// Resolve server address
	serverAddr, err := net.ResolveTCPAddr("tcp", c.ServerAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to resolve STUN server address %s: %w", c.ServerAddr, err)
	}

	// Create STUN message
	msg, err := CreateStunMessage(stunBindingRequest, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to create STUN request: %w", err)
	}

	err = AddFingerprint(msg)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to add fingerprint: %w", err)
	}

	// Send request and receive response
	responseBytes, err := c.sendStunRequestTCP(serverAddr, connOrSrcPort, msg.Raw, msg.Header.TransactionID)
	if err != nil {
		return nil, 0, err
	}

	// Parse and validate response
	response, err := ParseStunMessage(responseBytes)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse STUN response: %w", err)
	}

	if err := ValidateStunMessage(response, stunBindingResponse, msg.Header.TransactionID); err != nil {
		return nil, 0, fmt.Errorf("invalid STUN response: %w", err)
	}

	// Verify FINGERPRINT attribute (RFC 5389 Section 15.5)
	/*if !VerifyFingerprint(response) {
		return nil, 0, fmt.Errorf("invalid STUN response: fingerprint verification failed")
	}*/

	// Check for error response first
	if response.Header.Type == stunBindingErrorResponse {
		errorCode, errorReason := ParseStunError(response.Attributes)
		return nil, 0, fmt.Errorf("STUN error %d: %s", errorCode, errorReason)
	}

	// Extract mapped address
	mappedIP, mappedPort, err = ExtractMappedAddress(response.Attributes)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to extract mapped address: %w", err)
	}

	if c.logger != nil {
		c.logger.Infof("STUN: Found mapped address %s:%d (TCP)", mappedIP, mappedPort)
	}

	return mappedIP, mappedPort, nil
}

// sendStunRequestTCP sends a STUN TCP request and receives the response.
// connOrSrcPort is the TCP connection or the source port to send from.
func (c *StunClient) sendStunRequestTCP(serverAddr *net.TCPAddr, connOrSrcPort any, requestBytes []byte, txID [12]byte) (responseBytes []byte, err error) {
	var tcpConn *net.TCPConn
	// Check if we received an existing connection or need to create one
	tcpConn, ok := connOrSrcPort.(*net.TCPConn)
	if !ok {
		srcPort, ok := connOrSrcPort.(int)
		if !ok {
			return nil, fmt.Errorf("invalid source port: %v", connOrSrcPort)
		}
		// Create a new TCP connection
		tcpConn, err = createTCPConnection(serverAddr, srcPort)
		if err != nil {
			return nil, err
		}
		// Only close the connection if we created it
		defer tcpConn.Close()
	}
	return c.sendStunRequestConn(serverAddr, tcpConn, requestBytes, txID)
}

// createTCPConnection creates a TCP connection to the STUN server from the specified local port.
func createTCPConnection(serverAddr *net.TCPAddr, srcPort int) (*net.TCPConn, error) {
	// For TCP, we need to create a local endpoint and then dial the server
	laddr := &net.TCPAddr{
		IP:   net.IPv4zero, // Listen on all available IPs
		Port: srcPort,
	}

	conn, err := conn.DialTCP("tcp", laddr, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to STUN server %s from port %d: %w",
			serverAddr, srcPort, err)
	}
	return conn, nil
}
