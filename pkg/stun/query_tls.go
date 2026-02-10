package stun

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/common"
)

// QueryServerTLS is a convenience function that queries a STUN server over TLS.
// It discovers the IP address and port as seen from the public internet.
func QueryServerTLS(logger common.Logger, stunServerAddr string, connOrLocalAddr any, tlsConfig *tls.Config) (mappedIP net.IP, mappedPort int, err error) {
	client := NewStunClient(logger, stunServerAddr, tlsConfig)
	return client.QueryStunServerTLS(connOrLocalAddr)
}

// QueryStunServerTLS takes a TLS connection or a source port and queries the STUN server over TLS.
// This method discovers your public IP address and port as seen from the internet.
// It accepts either an existing TLS connection (*net.TCPConn) or a local address (*net.TCPAddr).
// If a source port is provided, a new TLS connection will be established and closed after the query.
func (c *StunClient) QueryStunServerTLS(connOrLocalAddr any) (mappedIP net.IP, mappedPort int, err error) {
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
		return c.queryStunServerTLS(serverAddr, conn)
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
	return c.queryStunServerTLS(serverAddr, localAddr)
}

// queryStunServerTLS sends a STUN Binding Request over TLS and returns the mapped IP and port.
// It uses the client's configured ServerAddr. connOrLocalAddr is the TLS connection or the local address to send from.
func (c *StunClient) queryStunServerTLS(serverAddr *net.TCPAddr, connOrLocalAddr any) (mappedIP net.IP, mappedPort int, err error) {
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
	responseBytes, err := c.sendStunRequestTLS(serverAddr, connOrLocalAddr, msg.Raw, msg.Header.TransactionID)
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
		c.logger.Infof("STUN: Found mapped address %s:%d (TLS)", mappedIP, mappedPort)
	}

	return mappedIP, mappedPort, nil
}

// sendStunRequestTLS sends a STUN TLS request and receives the response.
// connOrLocalAddr is the TLS connection or the local address to send from.
func (c *StunClient) sendStunRequestTLS(serverAddr *net.TCPAddr, connOrLocalAddr any, requestBytes []byte, txID [12]byte) (responseBytes []byte, err error) {
	var tlsConn *tls.Conn
	// Check if we received an existing connection or need to create one
	tlsConn, ok := connOrLocalAddr.(*tls.Conn)
	if !ok {
		laddr, ok := connOrLocalAddr.(*net.TCPAddr)
		if !ok {
			return nil, fmt.Errorf("invalid source port: %v", connOrLocalAddr)
		}
		// Create a new TLS connection
		tlsConn, err = createTLSConnection(serverAddr, laddr, c.TLSConfig)
		if err != nil {
			return nil, err
		}
		// Only close the connection if we created it
		defer tlsConn.Close()
	}
	return c.sendStunRequestConn(serverAddr, tlsConn, requestBytes, txID)
}

// createTLSConnection creates a TLS connection to the STUN server from the specified local port.
func createTLSConnection(serverAddr *net.TCPAddr, laddr *net.TCPAddr, tlsConfig *tls.Config) (*tls.Conn, error) {
	tcpConn, err := createTCPConnection(serverAddr, laddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS connection: %w", err)
	}
	tlsConn := tls.Client(tcpConn, tlsConfig)
	return tlsConn, nil
}
