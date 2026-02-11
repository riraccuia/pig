package stun

import (
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/network"
)

// QueryServerTCP is a convenience function that queries a STUN server over TCP.
// It discovers the IP address and port as seen from the public internet.
func QueryServerTCP(logger common.Logger, stunServerAddr string, connOrLocalAddr any) (mappedIP net.IP, mappedPort int, err error) {
	client := NewStunClient(logger, stunServerAddr, nil)
	return client.QueryStunServerTCP(connOrLocalAddr)
}

// QueryStunServerTCP takes a TCP connection or a source port and queries the STUN server over TCP.
// This method discovers your public IP address and port as seen from the internet.
// It accepts either an existing TCP connection (*net.TCPConn) or a local address (*net.TCPAddr).
// If a source port is provided, a new TCP connection will be established and closed after the query.
func (c *StunClient) QueryStunServerTCP(connOrLocalAddr any) (mappedIP net.IP, mappedPort int, err error) {
	conn, ok := connOrLocalAddr.(*net.TCPConn)
	if ok {
		network := "tcp4"
		if conn.LocalAddr().(*net.TCPAddr).IP.To4() == nil {
			network = "tcp6"
		}
		serverAddr, err := net.ResolveTCPAddr(network, c.ServerAddr)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to resolve STUN server address %s: %w", c.ServerAddr, err)
		}
		return c.queryStunServerTCP(serverAddr, conn)
	}
	localAddr, ok := connOrLocalAddr.(*net.TCPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("invalid local address: %v", connOrLocalAddr)
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
	serverAddr, err := net.ResolveTCPAddr(network, c.ServerAddr)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to resolve STUN server address %s: %w", c.ServerAddr, err)
	}
	return c.queryStunServerTCP(serverAddr, localAddr)
}

// queryStunServerTCP sends a STUN Binding Request over TCP and returns the mapped IP and port.
// It uses the client's configured ServerAddr. connOrLocalAddr is the TCP connection or the local address to send from.
func (c *StunClient) queryStunServerTCP(serverAddr *net.TCPAddr, connOrLocalAddr any) (mappedIP net.IP, mappedPort int, err error) {
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
	responseBytes, err := c.sendStunRequestTCP(serverAddr, connOrLocalAddr, msg.Raw, msg.Header.TransactionID)
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
	mappedIP, mappedPort, err = ExtractMappedAddress(response.Attributes, response.Header.TransactionID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to extract mapped address: %w", err)
	}

	if c.logger != nil {
		c.logger.Infof("STUN: Found mapped address %s:%d (TCP)", mappedIP, mappedPort)
	}

	return mappedIP, mappedPort, nil
}

// sendStunRequestTCP sends a STUN TCP request and receives the response.
// connOrLocalAddr is the TCP connection or the local address to send from.
func (c *StunClient) sendStunRequestTCP(serverAddr *net.TCPAddr, connOrLocalAddr any, requestBytes []byte, txID [12]byte) (responseBytes []byte, err error) {
	var tcpConn *net.TCPConn
	// Check if we received an existing connection or need to create one
	tcpConn, ok := connOrLocalAddr.(*net.TCPConn)
	if !ok {
		laddr, ok := connOrLocalAddr.(*net.TCPAddr)
		if !ok {
			return nil, fmt.Errorf("invalid local address: %v", connOrLocalAddr)
		}
		// Create a new TCP connection
		tcpConn, err = createTCPConnection(serverAddr, laddr)
		if err != nil {
			return nil, err
		}
		// Only close the connection if we created it
		defer tcpConn.Close()
	}
	return c.sendStunRequestConn(serverAddr, tcpConn, requestBytes, txID)
}

// createTCPConnection creates a TCP connection to the STUN server from the specified local port.
func createTCPConnection(serverAddr *net.TCPAddr, laddr *net.TCPAddr) (*net.TCPConn, error) {
	conn, err := network.DialTCP("tcp", laddr, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to STUN server %s from %s: %w",
			serverAddr, laddr, err)
	}
	return conn, nil
}
