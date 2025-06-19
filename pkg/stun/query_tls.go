package stun

import (
	"crypto/tls"
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/common"
)

// QueryServerTLS is a convenience function that queries a STUN server over TLS.
// It discovers the IP address and port as seen from the public internet.
func QueryServerTLS(logger common.Logger, stunServerAddr string, connOrSrcPort any, tlsConfig *tls.Config) (mappedIP net.IP, mappedPort int, err error) {
	client := NewStunClient(logger, stunServerAddr, tlsConfig)
	return client.QueryStunServerTLS(connOrSrcPort)
}

// QueryStunServerTLS takes a TLS connection or a source port and queries the STUN server over TLS.
// This method discovers your public IP address and port as seen from the internet.
// It accepts either an existing TLS connection (*tls.Conn) or a source port number (int).
// If a source port is provided, a new TLS connection will be established and closed after the query.
func (c *StunClient) QueryStunServerTLS(connOrSrcPort any) (mappedIP net.IP, mappedPort int, err error) {
	conn, ok := connOrSrcPort.(*tls.Conn)
	if ok {
		c.ServerAddr = conn.RemoteAddr().String()
		return c.queryStunServerTLS(conn)
	}
	srcPort, ok := connOrSrcPort.(int)
	if !ok {
		return nil, 0, fmt.Errorf("invalid source port: %v", connOrSrcPort)
	}
	return c.queryStunServerTLS(srcPort)
}

// queryStunServerTLS sends a STUN Binding Request over TLS and returns the mapped IP and port.
// It uses the client's configured ServerAddr. connOrSrcPort is the TLS connection or the source port to send from.
func (c *StunClient) queryStunServerTLS(connOrSrcPort any) (mappedIP net.IP, mappedPort int, err error) {
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
	responseBytes, err := c.sendStunRequestTLS(serverAddr, connOrSrcPort, msg.Raw, msg.Header.TransactionID)
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
	mappedIP, mappedPort, err = ExtractMappedAddress(response.Attributes)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to extract mapped address: %w", err)
	}

	if c.logger != nil {
		c.logger.Infof("STUN: Found mapped address %s:%d (TLS)", mappedIP, mappedPort)
	}

	return mappedIP, mappedPort, nil
}

// sendStunRequestTLS sends a STUN TLS request and receives the response.
// connOrSrcPort is the TLS connection or the source port to send from.
func (c *StunClient) sendStunRequestTLS(serverAddr *net.TCPAddr, connOrSrcPort any, requestBytes []byte, txID [12]byte) (responseBytes []byte, err error) {
	var tlsConn *tls.Conn
	// Check if we received an existing connection or need to create one
	tlsConn, ok := connOrSrcPort.(*tls.Conn)
	if !ok {
		srcPort, ok := connOrSrcPort.(int)
		if !ok {
			return nil, fmt.Errorf("invalid source port: %v", connOrSrcPort)
		}
		// Create a new TLS connection
		tlsConn, err = createTLSConnection(serverAddr, srcPort, c.TLSConfig)
		if err != nil {
			return nil, err
		}
		// Only close the connection if we created it
		defer tlsConn.Close()
	}
	return c.sendStunRequestConn(serverAddr, tlsConn, requestBytes, txID)
}

// createTLSConnection creates a TLS connection to the STUN server from the specified local port.
func createTLSConnection(serverAddr *net.TCPAddr, srcPort int, tlsConfig *tls.Config) (*tls.Conn, error) {
	tcpConn, err := createTCPConnection(serverAddr, srcPort)
	if err != nil {
		return nil, fmt.Errorf("failed to create TLS connection: %w", err)
	}
	tlsConn := tls.Client(tcpConn, tlsConfig)
	return tlsConn, nil
}
