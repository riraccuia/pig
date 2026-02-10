package stun

import (
	"fmt"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/ice/conn"
)

// QueryServerUDP is a convenience function that uses a StunClient under the hood.
func QueryServerUDP(logger common.Logger, stunServerAddr string, connOrLocalAddr any) (mappedIP net.IP, mappedPort int, err error) {
	client := NewStunClient(logger, stunServerAddr, nil)
	return client.QueryStunServerUDP(connOrLocalAddr)
}

// QueryStunServerUDP takes a UDP connection or a source port and queries the STUN server.
func (c *StunClient) QueryStunServerUDP(connOrLocalAddr any) (mappedIP net.IP, mappedPort int, err error) {
	conn, ok := connOrLocalAddr.(*net.UDPConn)
	if ok {
		network := "udp4"
		if conn.LocalAddr().(*net.UDPAddr).IP.To4() == nil {
			network = "udp6"
		}
		serverAddr, err := net.ResolveUDPAddr(network, c.ServerAddr)
		if err != nil {
			return nil, 0, fmt.Errorf("failed to resolve STUN server address %s: %w", c.ServerAddr, err)
		}
		return c.queryStunServerUDP(serverAddr, conn)
	}
	localAddr, ok := connOrLocalAddr.(*net.UDPAddr)
	if !ok {
		return nil, 0, fmt.Errorf("invalid local address: %v", connOrLocalAddr)
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
		return nil, 0, fmt.Errorf("failed to resolve STUN server address %s: %w", c.ServerAddr, err)
	}
	return c.queryStunServerUDP(serverAddr, localAddr)
}

// QueryStunServerUDP sends a STUN Binding Request and returns the mapped IP and port.
// It uses the client's configured ServerAddr. connOrLocalAddr is the UDP connection or the local address to send from.
func (c *StunClient) queryStunServerUDP(serverAddr *net.UDPAddr, connOrLocalAddr any) (mappedIP net.IP, mappedPort int, err error) {
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
	responseBytes, err := c.sendStunRequestUDP(serverAddr, connOrLocalAddr, msg.Raw, msg.Header.TransactionID)
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

	// Verify FINGERPRINT attribute (RFC 5389 Section 15.5)
	/*if !VerifyFingerprint(response) {
		return nil, 0, fmt.Errorf("invalid STUN response: fingerprint verification failed")
	}*/

	// Extract mapped address
	mappedIP, mappedPort, err = ExtractMappedAddress(response.Attributes, response.Header.TransactionID)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to extract mapped address: %w", err)
	}

	if c.logger != nil {
		c.logger.Infof("STUN: Found mapped address %s:%d (UDP)", mappedIP, mappedPort)
	}

	return mappedIP, mappedPort, nil
}

// sendStunRequestUDP sends a STUN UDP request and receives the response.
// connOrSrcPort is the UDP connection or the source port to send from.
func (c *StunClient) sendStunRequestUDP(serverAddr *net.UDPAddr, connOrLocalAddr any, requestBytes []byte, txID [12]byte) (responseBytes []byte, err error) {
	udpConn, ok := connOrLocalAddr.(net.Conn)
	if !ok {
		laddr, ok := connOrLocalAddr.(*net.UDPAddr)
		if !ok {
			return nil, fmt.Errorf("invalid local address: %v", connOrLocalAddr)
		}
		var _udpConn *net.UDPConn
		_udpConn, err = conn.DialUDP("udp", laddr, serverAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to dial UDP: %w", err)
		}
		udpConn = conn.NewUDPPacketConn(_udpConn)
		// only close the connection if we created it
		defer udpConn.Close()
	}

	srcPort := udpConn.LocalAddr().(*net.UDPAddr).Port

	if c.logger != nil {
		c.logger.Infof("STUN: Sending Binding Request over UDP from :%d to %s (TX ID: %x)", srcPort, serverAddr, txID[:4])
	}

	// Send request
	_, err = udpConn.Write(requestBytes)
	//_, err = udpConn.WriteToUDP(requestBytes, serverAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to send STUN request over UDP: %w", err)
	}

	// Receive response with timeout
	responseBytes = make([]byte, 1500) // MTU size buffer
	udpConn.SetReadDeadline(time.Now().Add(stunTimeout))
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

	if c.logger != nil {
		c.logger.Debugf("STUN: Received %d bytes response over UDP from %s", n, serverAddr)
	}

	return responseBytes, nil
}
