package stun

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/common"
)

func QueryServer(logger common.Logger, stunServer string, sourcePort int, protocol string, tlsConfig *tls.Config) (mappedIP net.IP, mappedPort int, err error) {
	switch protocol {
	case "udp":
		return QueryServerUDP(logger, stunServer, &net.UDPAddr{IP: nil, Port: sourcePort})
	case "tcp":
		return QueryServerTCP(logger, stunServer, &net.TCPAddr{IP: nil, Port: sourcePort})
	case "tls":
		if tlsConfig == nil {
			return nil, 0, fmt.Errorf("TLS config is required for TLS queries")
		}
		return QueryServerTLS(logger, stunServer, &net.TCPAddr{IP: nil, Port: sourcePort}, tlsConfig)
	default:
		return nil, 0, fmt.Errorf("invalid protocol: %s", protocol)
	}
}

// sendStunRequestConn sends a STUN TCP request and receives the response.
// conn is the TCP or TLS connection to send from.
func (c *StunClient) sendStunRequestConn(serverAddr *net.TCPAddr, conn net.Conn, requestBytes []byte, txID [12]byte) (responseBytes []byte, err error) {
	srcPort := conn.LocalAddr().(*net.TCPAddr).Port

	if c.logger != nil {
		c.logger.Infof("STUN: Sending Binding Request over %s from :%d to %s (TX ID: %x)",
			conn.LocalAddr().Network(), srcPort, serverAddr, txID[:4])
	}

	// Set timeouts
	conn.SetDeadline(time.Now().Add(stunTimeout))
	defer conn.SetDeadline(time.Time{})

	// Send request
	_, err = conn.Write(requestBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to send STUN request over TCP: %w", err)
	}

	// Receive response - read the full 20-byte header first
	responseHeader := make([]byte, 20)
	_, err = conn.Read(responseHeader)
	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return nil, fmt.Errorf("STUN TCP request timed out")
		}
		return nil, fmt.Errorf("failed to read STUN response header: %w", err)
	}

	// Parse the length from the header to determine how many more bytes to read
	messageLength := int(binary.BigEndian.Uint16(responseHeader[2:4]))

	// Allocate buffer for the complete message (header + attributes)
	responseBytes = make([]byte, 20+messageLength)
	copy(responseBytes, responseHeader)

	// Read the rest of the message if there are attributes
	if messageLength > 0 {
		bytesRead := 0
		for bytesRead < messageLength {
			n, err := conn.Read(responseBytes[20+bytesRead:])
			if err != nil {
				return nil, fmt.Errorf("failed to read STUN response attributes: %w", err)
			}
			bytesRead += n
			if bytesRead >= messageLength {
				break
			}
		}
	}

	if c.logger != nil {
		c.logger.Debugf("STUN: Received %d bytes response over TCP from %s", len(responseBytes), serverAddr)
	}

	return responseBytes, nil
}

func processStunRequestBytes(reqBytes []byte, remoteAddr net.Addr) (*StunMessage, error) {
	request, err := ParseStunMessage(reqBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse STUN request: %w", err)
	}

	// Validate request type
	if request.Header.Type != stunBindingRequest {
		return nil, fmt.Errorf("unexpected STUN message type: 0x%x", request.Header.Type)
	}

	if !VerifyFingerprint(request) {
		return nil, fmt.Errorf("invalid STUN request: fingerprint verification failed")
	}

	// Create response attributes
	responseAttrs, err := CreateResponseAttributes(remoteAddr, request.Header.TransactionID, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create response attributes: %w", err)
	}

	// Create response without MESSAGE-INTEGRITY first
	response, err := CreateStunMessage(stunBindingResponse, responseAttrs)
	if err != nil {
		return nil, fmt.Errorf("failed to create STUN response: %w", err)
	}

	// Copy transaction ID from request
	CopyTransactionID(response, request)

	err = AddFingerprint(response)
	if err != nil {
		return nil, fmt.Errorf("failed to add fingerprint: %w", err)
	}

	return response, nil
}
