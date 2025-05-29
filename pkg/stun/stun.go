package stun

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/common"
)

// --- STUN Constants (RFC 5389) ---
const (
	stunBindingRequest   uint16 = 0x0001
	stunBindingResponse  uint16 = 0x0101
	stunMagicCookie      uint32 = 0x2112A442
	attrXorMappedAddress uint16 = 0x0020
	attrErrorCode        uint16 = 0x0009
	stunTimeout                 = 3 * time.Second
)

// StunClient represents a STUN client with configurable settings
type StunClient struct {
	logger     common.Logger
	ServerAddr string
	TLSConfig  *tls.Config
}

// NewStunClient creates a new STUN client instance
func NewStunClient(logger common.Logger, serverAddr string, tlsConfig *tls.Config) *StunClient {
	return &StunClient{
		logger:     logger,
		ServerAddr: serverAddr,
		TLSConfig:  tlsConfig,
	}
}

// stunHeader represents the STUN message header.
type stunHeader struct {
	Type          uint16
	Length        uint16
	MagicCookie   uint32
	TransactionID [12]byte
}

// createStunRequest generates a transaction ID and builds a STUN Binding Request.
func (c *StunClient) createStunRequest() (txID [12]byte, requestBytes []byte, err error) {
	// Generate random transaction ID
	if _, err := rand.Read(txID[:]); err != nil {
		return txID, nil, fmt.Errorf("failed to generate transaction ID: %w", err)
	}

	// Build request header
	reqHeader := stunHeader{
		Type:          stunBindingRequest,
		Length:        0, // No attributes in request
		MagicCookie:   stunMagicCookie,
		TransactionID: txID,
	}

	// Marshal header to bytes
	reqBuf := new(bytes.Buffer)
	if err := binary.Write(reqBuf, binary.BigEndian, reqHeader); err != nil {
		return txID, nil, fmt.Errorf("failed to marshal STUN request header: %w", err)
	}

	return txID, reqBuf.Bytes(), nil
}

// validateStunResponse validates the STUN response header against expected values.
func (c *StunClient) validateStunResponse(responseBytes []byte, txID [12]byte) error {
	// Check minimum length
	if len(responseBytes) < 20 {
		return fmt.Errorf("STUN response too short: %d bytes", len(responseBytes))
	}

	// Parse header
	var respHeader stunHeader
	respBuf := bytes.NewReader(responseBytes)
	if err := binary.Read(respBuf, binary.BigEndian, &respHeader); err != nil {
		return fmt.Errorf("failed to parse STUN response header: %w", err)
	}

	// Check message type
	if respHeader.Type != stunBindingResponse {
		c.logger.Errorf("STUN: Received unexpected message type 0x%x", respHeader.Type)
		errorCode, errorReason := c.parseStunError(responseBytes[20:])
		if errorCode != 0 {
			return fmt.Errorf("STUN server returned error %d: %s", errorCode, errorReason)
		}
		return fmt.Errorf("unexpected STUN message type: 0x%x", respHeader.Type)
	}

	// Check magic cookie
	if respHeader.MagicCookie != stunMagicCookie {
		return errors.New("invalid STUN magic cookie in response")
	}

	// Check transaction ID
	if respHeader.TransactionID != txID {
		return errors.New("STUN transaction ID mismatch")
	}

	// Check length field matches actual data length
	if len(responseBytes) != int(respHeader.Length)+20 {
		return fmt.Errorf("STUN message length mismatch: header says %d bytes attributes, received %d",
			respHeader.Length, len(responseBytes)-20)
	}

	return nil
}

// extractMappedAddress parses STUN attributes to find and decode XOR-MAPPED-ADDRESS.
func (c *StunClient) extractMappedAddress(attributes []byte) (mappedIP net.IP, mappedPort int, err error) {
	offset := 0
	for offset < len(attributes) {
		// Ensure we have enough bytes for the attribute header
		if offset+4 > len(attributes) {
			return nil, 0, errors.New("invalid STUN attribute section (header too short)")
		}

		// Read attribute type and length
		attrType := binary.BigEndian.Uint16(attributes[offset : offset+2])
		attrLen := binary.BigEndian.Uint16(attributes[offset+2 : offset+4])
		offset += 4

		// Ensure we have enough bytes for the attribute value
		if offset+int(attrLen) > len(attributes) {
			return nil, 0, errors.New("invalid STUN attribute section (value length exceeds bounds)")
		}
		attrValue := attributes[offset : offset+int(attrLen)]

		// Check if this is the XOR-MAPPED-ADDRESS attribute
		if attrType == attrXorMappedAddress {
			ip, port, found, err := c.decodeXorMappedAddress(attrValue, attrLen)
			if err != nil {
				// Log error but continue to look for other attributes
				c.logger.Errorf("STUN: Error parsing XOR-MAPPED-ADDRESS: %v", err)
			}
			if found {
				return ip, port, nil
			}
		}

		// Move to the next attribute (with padding)
		paddedLen := (int(attrLen) + 3) &^ 3
		offset += paddedLen
	}

	return nil, 0, errors.New("XOR-MAPPED-ADDRESS attribute not found in STUN response")
}

// decodeXorMappedAddress parses an XOR-MAPPED-ADDRESS attribute.
// Returns the IP, port, whether it was successfully found, and any error.
func (c *StunClient) decodeXorMappedAddress(attrValue []byte, attrLen uint16) (net.IP, int, bool, error) {
	// Minimum length check (family, port, at least one IP byte)
	if attrLen < 4 {
		return nil, 0, false, fmt.Errorf("XOR-MAPPED-ADDRESS attribute too short (%d bytes)", attrLen)
	}

	// Extract family byte (IPv4 = 0x01, IPv6 = 0x02)
	family := attrValue[1]
	if family != 0x01 {
		return nil, 0, false, fmt.Errorf("unsupported address family: %d (only IPv4 supported)", family)
	}

	// For IPv4, we expect 8 bytes total
	if attrLen != 8 {
		return nil, 0, false, fmt.Errorf("unexpected attribute length for IPv4: %d", attrLen)
	}

	// Extract port (XOR with first 16 bits of magic cookie)
	xPort := binary.BigEndian.Uint16(attrValue[2:4])
	port := int(xPort ^ uint16(stunMagicCookie>>16))

	// Extract IP (XOR with magic cookie)
	xIPBytes := attrValue[4:8]
	magicCookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(magicCookieBytes, stunMagicCookie)

	ipBytes := make([]byte, 4)
	for i := 0; i < 4; i++ {
		ipBytes[i] = xIPBytes[i] ^ magicCookieBytes[i]
	}

	ip := net.IP(ipBytes)

	if c.logger != nil {
		c.logger.Debugf("STUN: Found XOR-MAPPED-ADDRESS: %s:%d", ip, port)
	}

	return ip, port, true, nil
}

// parseStunError extracts error code and reason from STUN error attributes.
func (c *StunClient) parseStunError(attributes []byte) (code int, reason string) {
	offset := 0
	for offset < len(attributes) {
		// Ensure we have enough bytes for the attribute header
		if offset+4 > len(attributes) {
			break
		}

		// Read attribute type and length
		attrType := binary.BigEndian.Uint16(attributes[offset : offset+2])
		attrLen := binary.BigEndian.Uint16(attributes[offset+2 : offset+4])
		offset += 4

		// Ensure we have enough bytes for the attribute value
		if offset+int(attrLen) > len(attributes) {
			break
		}
		attrValue := attributes[offset : offset+int(attrLen)]

		// Parse ERROR-CODE attribute if found
		if attrType == attrErrorCode {
			if len(attrValue) >= 4 {
				// Error code structure: [0, 0, Class, Number] followed by Reason
				class := int(attrValue[2] >> 3 & 0x07)
				number := int(attrValue[3])
				code = class*100 + number

				if len(attrValue) > 4 {
					reason = string(attrValue[4:])
				} else {
					reason = "Unknown reason"
				}
				return code, reason
			}
			break
		}

		// Move to the next attribute (with padding)
		paddedLen := (int(attrLen) + 3) &^ 3
		offset += paddedLen
	}

	return 0, ""
}
