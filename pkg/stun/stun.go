package stun

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/riraccuia/pig/pkg/common"
)

// --- STUN Constants (RFC 5389) ---
const (
	// STUN message types
	stunBindingRequest       uint16 = 0x0001
	stunBindingResponse      uint16 = 0x0101
	stunBindingErrorResponse uint16 = 0x0111

	// STUN attribute types
	attrUsername         uint16 = 0x0006
	attrMessageIntegrity uint16 = 0x0008
	attrErrorCode        uint16 = 0x0009
	attrRealm            uint16 = 0x0014
	attrNonce            uint16 = 0x0015
	attrXorMappedAddress uint16 = 0x0020

	// ICE attribute types
	attrPriority       uint16 = 0x0024
	attrUseCandidate   uint16 = 0x0025
	attrIceControlling uint16 = 0x8029
	attrIceControlled  uint16 = 0x802A

	// FINGERPRINT attribute type (RFC 5389 Section 15.5)
	attrFingerprint uint16 = 0x8028
	// FINGERPRINT XOR value (RFC 5389 Section 15.5)
	fingerprintXorValue uint32 = 0x5354554e

	// STUN magic cookie value
	stunMagicCookie uint32 = 0x2112A442

	attrStunError uint16 = 0x0009
	stunTimeout          = 3 * time.Second
)

// StunMessage represents a STUN message with its header and attributes
type StunMessage struct {
	Header     stunHeader
	Attributes []byte
	Raw        []byte
}

// stunHeader represents the STUN message header.
type stunHeader struct {
	Type          uint16
	Length        uint16
	MagicCookie   uint32
	TransactionID [12]byte
}

// StunError represents a STUN error response
type StunError struct {
	Code   int
	Reason string
}

// StunAuthConfig represents STUN authentication configuration
type StunAuthConfig struct {
	// For ICE, username is formed as "peer_frag:local_frag"
	// See RFC 8445 Section 7.2.2
	SendUsername string // peer_frag:local_frag
	Username     string // local_frag
	Password     string
	Realm        string
	Nonce        string
}

// IceAttributes represents ICE-specific STUN attributes
type IceAttributes struct {
	Priority       uint32
	UseCandidate   bool
	IceControlling uint64
	IceControlled  uint64
}

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

// CreateStunMessage creates a new STUN message with the given type and attributes
func CreateStunMessage(msgType uint16, attributes []byte) (*StunMessage, error) {
	// Generate random transaction ID
	txID := [12]byte{}
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, fmt.Errorf("failed to generate transaction ID: %w", err)
	}

	// Create header
	header := stunHeader{
		Type:          msgType,
		Length:        uint16(len(attributes)),
		MagicCookie:   stunMagicCookie,
		TransactionID: txID,
	}

	// Build complete message
	msg := make([]byte, 20+len(attributes))
	binary.BigEndian.PutUint16(msg[0:2], header.Type)
	binary.BigEndian.PutUint16(msg[2:4], header.Length)
	binary.BigEndian.PutUint32(msg[4:8], header.MagicCookie)
	copy(msg[8:20], header.TransactionID[:])
	if len(attributes) > 0 {
		copy(msg[20:], attributes)
	}

	return &StunMessage{
		Header:     header,
		Attributes: attributes,
		Raw:        msg,
	}, nil
}

// ParseStunMessage parses a raw STUN message into its components
func ParseStunMessage(data []byte) (*StunMessage, error) {
	if len(data) < 20 {
		return nil, fmt.Errorf("STUN message too short: %d bytes", len(data))
	}

	var header stunHeader
	header.Type = binary.BigEndian.Uint16(data[0:2])
	header.Length = binary.BigEndian.Uint16(data[2:4])
	header.MagicCookie = binary.BigEndian.Uint32(data[4:8])
	copy(header.TransactionID[:], data[8:20])

	// Ensure we have enough data for the attributes
	if len(data) < 20+int(header.Length) {
		return nil, fmt.Errorf("STUN message truncated: expected %d bytes, got %d", 20+int(header.Length), len(data))
	}

	// Extract attributes, ensuring we don't read past the message length
	attributes := data[20 : 20+int(header.Length)]

	return &StunMessage{
		Header:     header,
		Attributes: attributes,
		Raw:        data,
	}, nil
}

// ValidateStunMessage validates a STUN message
func ValidateStunMessage(msg *StunMessage, expectedType uint16, expectedTxID [12]byte) error {
	if msg.Header.Type != expectedType {
		return fmt.Errorf("unexpected message type: 0x%x", msg.Header.Type)
	}

	if msg.Header.MagicCookie != stunMagicCookie {
		return errors.New("invalid STUN magic cookie")
	}

	if msg.Header.TransactionID != expectedTxID {
		return errors.New("transaction ID mismatch")
	}

	return nil
}

// CreateXorMappedAddress creates an XOR-MAPPED-ADDRESS attribute
func CreateXorMappedAddress(addr net.Addr) ([]byte, error) {
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to parse address: %w", err)
	}

	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", host)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port: %s", portStr)
	}

	var (
		family     byte = 0x01 // default to IPv4
		addrBytes  []byte
		attrLength uint16
	)

	if ip.To4() == nil {
		family = 0x02 // IPv6
	}

	switch family {
	case 0x01:
		addrBytes = ip.To4()
		attrLength = 8 // 1 byte family + 1 byte port + 4 bytes IPv4
	case 0x02:
		addrBytes = ip.To16()
		attrLength = 20 // 1 byte family + 1 byte port + 16 bytes IPv6
	}

	// Create XOR-MAPPED-ADDRESS attribute
	xorMappedAddr := make([]byte, attrLength)
	xorMappedAddr[0] = 0 // Reserved
	xorMappedAddr[1] = family

	// XOR port with first 16 bits of magic cookie
	xorPort := uint16(port) ^ uint16(stunMagicCookie>>16)
	binary.BigEndian.PutUint16(xorMappedAddr[2:4], xorPort)

	// XOR IP address with magic cookie
	magicCookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(magicCookieBytes, stunMagicCookie)

	switch family {
	case 0x01:
		// IPv4: XOR with magic cookie
		for i := 0; i < 4; i++ {
			xorMappedAddr[4+i] = addrBytes[i] ^ magicCookieBytes[i]
		}
	case 0x02:
		// IPv6: XOR with magic cookie and transaction ID
		for i := 0; i < 4; i++ {
			xorMappedAddr[4+i] = addrBytes[i] ^ magicCookieBytes[i]
		}
		for i := 4; i < 16; i++ {
			xorMappedAddr[4+i] = addrBytes[i] ^ xorMappedAddr[i-4]
		}
	}

	// Create attribute header
	attr := make([]byte, 4+attrLength)
	binary.BigEndian.PutUint16(attr[0:2], attrXorMappedAddress)
	binary.BigEndian.PutUint16(attr[2:4], attrLength)
	copy(attr[4:], xorMappedAddr)

	return attr, nil
}

// CreateErrorResponse creates a STUN error response
func CreateErrorResponse(txID [12]byte, code int, reason string) ([]byte, error) {
	// Create error response header
	header := stunHeader{
		Type:          stunBindingErrorResponse,
		Length:        uint16(4 + len(reason)), // Length of ERROR-CODE attribute
		MagicCookie:   stunMagicCookie,
		TransactionID: txID,
	}

	// Create ERROR-CODE attribute
	errorAttr := make([]byte, 8+len(reason))
	binary.BigEndian.PutUint16(errorAttr[0:2], attrErrorCode)
	binary.BigEndian.PutUint16(errorAttr[2:4], uint16(4+len(reason)))
	errorAttr[4] = 0                // Reserved
	errorAttr[5] = byte(code / 100) // Class
	errorAttr[6] = byte(code % 100) // Number
	errorAttr[7] = 0                // Reserved
	copy(errorAttr[8:], []byte(reason))

	// Add padding to maintain 4-byte alignment
	padding := calculatePadding(len(reason))
	if padding > 0 {
		errorAttr = append(errorAttr, make([]byte, padding)...)
	}

	// Update header length to include padding
	header.Length = uint16(len(errorAttr))

	// Build complete response
	response := make([]byte, 20+len(errorAttr))
	binary.BigEndian.PutUint16(response[0:2], header.Type)
	binary.BigEndian.PutUint16(response[2:4], header.Length)
	binary.BigEndian.PutUint32(response[4:8], header.MagicCookie)
	copy(response[8:20], header.TransactionID[:])
	copy(response[20:], errorAttr)

	return response, nil
}

// ParseStunError extracts error code and reason from STUN error attributes
func ParseStunError(attributes []byte) (code int, reason string) {
	offset := 0
	for offset < len(attributes) {
		if offset+4 > len(attributes) {
			break
		}

		attrType := binary.BigEndian.Uint16(attributes[offset : offset+2])
		attrLen := binary.BigEndian.Uint16(attributes[offset+2 : offset+4])
		offset += 4

		if offset+int(attrLen) > len(attributes) {
			break
		}

		if attrType == attrErrorCode {
			if len(attributes[offset:]) >= 4 {
				class := int(attributes[offset+2] >> 3 & 0x07)
				number := int(attributes[offset+3])
				code = class*100 + number

				if len(attributes[offset:]) > 4 {
					reason = string(attributes[offset+4 : offset+4+int(attrLen-4)])
				}
				return code, reason
			}
			break
		}

		paddedLen := (int(attrLen) + 3) &^ 3
		offset += paddedLen
	}

	return 0, ""
}

// ExtractMappedAddress extracts the mapped address from a STUN response
func ExtractMappedAddress(attributes []byte) (net.IP, int, error) {
	offset := 0
	for offset < len(attributes) {
		if offset+4 > len(attributes) {
			break
		}

		attrType := binary.BigEndian.Uint16(attributes[offset : offset+2])
		attrLen := binary.BigEndian.Uint16(attributes[offset+2 : offset+4])
		offset += 4

		if offset+int(attrLen) > len(attributes) {
			break
		}

		if attrType != attrXorMappedAddress {
			paddedLen := (int(attrLen) + 3) &^ 3
			offset += paddedLen
			continue
		}

		family := attributes[offset+1]
		port := binary.BigEndian.Uint16(attributes[offset+2:offset+4]) ^ uint16(stunMagicCookie>>16)

		var ip net.IP
		switch family {
		case 0x01: // IPv4
			if offset+8 > len(attributes) {
				break
			}
			ip = make(net.IP, 4)
			for i := 0; i < 4; i++ {
				ip[i] = attributes[offset+4+i] ^ byte(stunMagicCookie>>((3-i)*8))
			}
		case 0x02: // IPv6
			if offset+20 > len(attributes) {
				break
			}
			ip = make(net.IP, 16)
			for i := 0; i < 4; i++ {
				ip[i] = attributes[offset+4+i] ^ byte(stunMagicCookie>>((3-i)*8))
			}
			for i := 4; i < 16; i++ {
				ip[i] = attributes[offset+4+i] ^ attributes[offset-16+i]
			}
		default:
			return nil, 0, fmt.Errorf("unsupported address family: %d", family)
		}

		return ip, int(port), nil
	}

	return nil, 0, errors.New("mapped address not found")
}

// CreateIceAttributes creates ICE-specific attributes
func CreateIceAttributes(ice *IceAttributes) []byte {
	var attributes []byte

	if ice.Priority > 0 {
		attr := make([]byte, 8)
		binary.BigEndian.PutUint16(attr[0:2], attrPriority)
		binary.BigEndian.PutUint16(attr[2:4], 4)
		binary.BigEndian.PutUint32(attr[4:8], ice.Priority)
		attributes = append(attributes, attr...)
	}

	if ice.UseCandidate {
		attr := make([]byte, 4)
		binary.BigEndian.PutUint16(attr[0:2], attrUseCandidate)
		binary.BigEndian.PutUint16(attr[2:4], 0)
		attributes = append(attributes, attr...)
	}

	if ice.IceControlling > 0 {
		attr := make([]byte, 12)
		binary.BigEndian.PutUint16(attr[0:2], attrIceControlling)
		binary.BigEndian.PutUint16(attr[2:4], 8)
		binary.BigEndian.PutUint64(attr[4:12], ice.IceControlling)
		attributes = append(attributes, attr...)
	}

	if ice.IceControlled > 0 {
		attr := make([]byte, 12)
		binary.BigEndian.PutUint16(attr[0:2], attrIceControlled)
		binary.BigEndian.PutUint16(attr[2:4], 8)
		binary.BigEndian.PutUint64(attr[4:12], ice.IceControlled)
		attributes = append(attributes, attr...)
	}

	return attributes
}

// ParseIceAttributes parses ICE-specific attributes from a STUN message
func ParseIceAttributes(data []byte) (*IceAttributes, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for ICE attributes")
	}

	ice := &IceAttributes{}
	offset := 0

	for offset < len(data) {
		// Check if we have enough bytes for the attribute header
		if offset+4 > len(data) {
			break
		}

		// Read attribute header
		attrType := binary.BigEndian.Uint16(data[offset:])
		attrLen := binary.BigEndian.Uint16(data[offset+2:])
		offset += 4

		// Check if we have enough bytes for the attribute value
		if offset+int(attrLen) > len(data) {
			break
		}

		// Read attribute value
		value := data[offset : offset+int(attrLen)]

		// Parse attribute based on type
		switch attrType {
		case attrPriority:
			if len(value) == 4 {
				ice.Priority = binary.BigEndian.Uint32(value)
			}
		case attrUseCandidate:
			ice.UseCandidate = true
		case attrIceControlling:
			if len(value) == 8 {
				ice.IceControlling = binary.BigEndian.Uint64(value)
			}
		case attrIceControlled:
			if len(value) == 8 {
				ice.IceControlled = binary.BigEndian.Uint64(value)
			}
		}

		// Move to next attribute (with padding)
		offset += int(attrLen)
		padding := calculatePadding(int(attrLen))
		offset += padding
	}

	return ice, nil
}

// CreateAuthAttributes creates authentication attributes
func CreateAuthAttributes(auth *StunAuthConfig) []byte {
	var attributes []byte

	// For ICE, username is formed as "peer_frag:local_frag"
	// See RFC 8445 Section 7.2.2
	if auth.SendUsername != "" {
		username := auth.SendUsername // peer_frag:local_frag format per RFC 8445 Section 7.2.2
		usernameBytes := []byte(username)
		attr := make([]byte, 4+len(usernameBytes))
		binary.BigEndian.PutUint16(attr[0:2], attrUsername)
		binary.BigEndian.PutUint16(attr[2:4], uint16(len(usernameBytes)))
		copy(attr[4:], usernameBytes)

		// Add padding to maintain 4-byte alignment
		padding := calculatePadding(len(usernameBytes))
		if padding > 0 {
			attr = append(attr, make([]byte, padding)...)
		}

		attributes = append(attributes, attr...)
	}

	if auth.Realm != "" {
		realmBytes := []byte(auth.Realm)
		attr := make([]byte, 4+len(realmBytes))
		binary.BigEndian.PutUint16(attr[0:2], attrRealm)
		binary.BigEndian.PutUint16(attr[2:4], uint16(len(realmBytes)))
		copy(attr[4:], realmBytes)

		// Add padding to maintain 4-byte alignment
		padding := calculatePadding(len(realmBytes))
		if padding > 0 {
			attr = append(attr, make([]byte, padding)...)
		}

		attributes = append(attributes, attr...)
	}

	if auth.Nonce != "" {
		nonceBytes := []byte(auth.Nonce)
		attr := make([]byte, 4+len(nonceBytes))
		binary.BigEndian.PutUint16(attr[0:2], attrNonce)
		binary.BigEndian.PutUint16(attr[2:4], uint16(len(nonceBytes)))
		copy(attr[4:], nonceBytes)

		// Add padding to maintain 4-byte alignment
		padding := calculatePadding(len(nonceBytes))
		if padding > 0 {
			attr = append(attr, make([]byte, padding)...)
		}

		attributes = append(attributes, attr...)
	}

	return attributes
}

// ParseAuthAttributes parses authentication attributes from raw bytes
func ParseAuthAttributes(data []byte) (*StunAuthConfig, error) {
	auth := &StunAuthConfig{}

	// Parse attributes
	for i := 0; i < len(data); {
		if i+4 > len(data) {
			break
		}

		attrType := binary.BigEndian.Uint16(data[i : i+2])
		attrLen := binary.BigEndian.Uint16(data[i+2 : i+4])

		if i+4+int(attrLen) > len(data) {
			break
		}

		switch attrType {
		case attrUsername:
			// For ICE, username is formed as "local_frag:peer_frag"
			// See RFC 8445 Section 7.2.2
			username := string(data[i+4 : i+4+int(attrLen)])
			parts := strings.Split(username, ":")
			if len(parts) == 2 {
				auth.Username = parts[0] // peer_frag
			} else {
				auth.Username = username
			}
		case attrRealm:
			auth.Realm = string(data[i+4 : i+4+int(attrLen)])
		case attrNonce:
			auth.Nonce = string(data[i+4 : i+4+int(attrLen)])
		}

		// Move to next attribute (including padding)
		i += 4 + int(attrLen)
		padding := calculatePadding(int(attrLen))
		i += padding
	}

	return auth, nil
}

// CalculateMessageIntegrity calculates the HMAC-SHA1 message integrity
// according to RFC 5389 Section 15.4
func CalculateMessageIntegrity(message []byte, password string) []byte {
	if password == "" || len(message) < 20 {
		return nil
	}

	// Find the position of the MESSAGE-INTEGRITY attribute if it exists
	var messageLen int
	for i := 20; i < len(message); {
		if i+4 > len(message) {
			break
		}
		attrType := binary.BigEndian.Uint16(message[i : i+2])
		attrLen := binary.BigEndian.Uint16(message[i+2 : i+4])

		if attrType == attrMessageIntegrity {
			messageLen = i
			break
		}

		i += 4 + int(attrLen)
		padding := calculatePadding(int(attrLen))
		i += padding
	}

	if messageLen == 0 {
		messageLen = len(message)
	}

	// Create a copy of the message up to the MESSAGE-INTEGRITY attribute
	msgCopy := make([]byte, messageLen)
	copy(msgCopy, message[:messageLen])

	// The length field in the STUN header needs to be adjusted to include
	// the size of the MESSAGE-INTEGRITY attribute (24 bytes = 4 byte header + 20 byte HMAC)
	// This is done BEFORE calculating the HMAC
	adjustedLength := uint16(messageLen - 20 + 24) // -20 for header, +24 for MESSAGE-INTEGRITY
	binary.BigEndian.PutUint16(msgCopy[2:4], adjustedLength)

	// For short-term credentials (used in ICE), use the password directly as the key
	// See RFC 5389 Section 15.4
	key := []byte(password)

	// Calculate HMAC-SHA1 using the key
	h := hmac.New(sha1.New, key)
	h.Write(msgCopy)
	return h.Sum(nil)
}

// CreateMessageIntegrityAttribute creates a MESSAGE-INTEGRITY attribute from the given integrity value
func CreateMessageIntegrityAttribute(integrity []byte) []byte {
	if integrity == nil {
		return nil
	}

	attr := make([]byte, 4+len(integrity))
	binary.BigEndian.PutUint16(attr[0:2], attrMessageIntegrity)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(integrity)))
	copy(attr[4:], integrity)

	// Add padding to maintain 4-byte alignment
	padding := calculatePadding(len(integrity))
	if padding > 0 {
		attr = append(attr, make([]byte, padding)...)
	}

	return attr
}

// CreateAuthenticatedErrorResponse creates a STUN error response with authentication attributes
func CreateAuthenticatedErrorResponse(txID [12]byte, code int, reason string, auth *StunAuthConfig) ([]byte, error) {
	// Create base error response
	response, err := CreateErrorResponse(txID, code, reason)
	if err != nil {
		return nil, fmt.Errorf("failed to create error response: %w", err)
	}

	if auth == nil {
		return response, nil
	}
	// If authentication is required, add auth attributes
	// Parse the current response
	msg, err := ParseStunMessage(response)
	if err != nil {
		return nil, fmt.Errorf("failed to parse error response: %w", err)
	}

	// Add authentication attributes
	authAttrs := CreateAuthAttributes(auth)
	if len(authAttrs) > 0 {
		msg.Attributes = append(msg.Attributes, authAttrs...)
	}

	// Recreate the response with auth attributes
	msg.Header.Length = uint16(len(msg.Attributes))
	response = make([]byte, 20+len(msg.Attributes))
	binary.BigEndian.PutUint16(response[0:2], msg.Header.Type)
	binary.BigEndian.PutUint16(response[2:4], msg.Header.Length)
	binary.BigEndian.PutUint32(response[4:8], msg.Header.MagicCookie)
	copy(response[8:20], msg.Header.TransactionID[:])
	copy(response[20:], msg.Attributes)

	return response, nil
}

// VerifyMessageIntegrity verifies the MESSAGE-INTEGRITY attribute in a STUN message
func VerifyMessageIntegrity(msg *StunMessage, password string) (bool, error) {
	if password == "" {
		return false, errors.New("password is required for message integrity verification")
	}

	// Find the MESSAGE-INTEGRITY attribute
	var messageIntegrity []byte
	for i := 0; i < len(msg.Attributes); {
		if i+4 > len(msg.Attributes) {
			break
		}
		attrType := binary.BigEndian.Uint16(msg.Attributes[i : i+2])
		attrLen := binary.BigEndian.Uint16(msg.Attributes[i+2 : i+4])
		if attrType == attrMessageIntegrity {
			messageIntegrity = msg.Attributes[i+4 : i+4+int(attrLen)]
			break
		}
		i += 4 + int(attrLen)
		padding := calculatePadding(int(attrLen))
		i += padding
	}

	if messageIntegrity == nil {
		return false, errors.New("message integrity attribute not found")
	}

	// Calculate expected message integrity
	expectedIntegrity := CalculateMessageIntegrity(msg.Raw, password)
	if expectedIntegrity == nil {
		return false, errors.New("failed to calculate message integrity")
	}

	// Compare message integrity values
	return bytes.Equal(messageIntegrity, expectedIntegrity), nil
}

// AddMessageIntegrity adds a MESSAGE-INTEGRITY attribute to a STUN message
// It handles the two-phase integrity calculation required by the STUN protocol:
// 1. Calculate initial integrity over the message
// 2. Add the integrity attribute
// 3. Recalculate integrity over the final message
// Returns the final message with integrity attribute
func AddMessageIntegrity(msg *StunMessage, password string) (*StunMessage, error) {
	if msg == nil || password == "" {
		return nil, fmt.Errorf("invalid input: message and password are required")
	}

	// Calculate initial message integrity
	integrity := CalculateMessageIntegrity(msg.Raw, password)
	if integrity == nil {
		return nil, fmt.Errorf("failed to calculate message integrity")
	}

	// Create MESSAGE-INTEGRITY attribute
	integrityAttr := CreateMessageIntegrityAttribute(integrity)
	if integrityAttr == nil {
		return nil, fmt.Errorf("failed to create message integrity attribute")
	}

	// Add MESSAGE-INTEGRITY attribute to existing attributes
	attributes := append(msg.Attributes, integrityAttr...)

	// Create new message with MESSAGE-INTEGRITY
	finalMsg, err := CreateStunMessage(msg.Header.Type, attributes)
	if err != nil {
		return nil, fmt.Errorf("failed to create final message: %w", err)
	}

	// Copy transaction ID since we created a new message
	copy(finalMsg.Header.TransactionID[:], msg.Header.TransactionID[:])
	copy(finalMsg.Raw[8:20], msg.Header.TransactionID[:])

	// Update the length field to include the MESSAGE-INTEGRITY attribute
	binary.BigEndian.PutUint16(finalMsg.Raw[2:4], uint16(len(finalMsg.Raw)-20))

	// Calculate final message integrity
	finalIntegrity := CalculateMessageIntegrity(finalMsg.Raw, password)
	if finalIntegrity == nil {
		return nil, fmt.Errorf("failed to calculate final message integrity")
	}

	// Update the MESSAGE-INTEGRITY attribute with the final value
	copy(finalMsg.Raw[len(finalMsg.Raw)-len(finalIntegrity):], finalIntegrity)

	return finalMsg, nil
}

// SendErrorResponse creates and sends a STUN error response with the given error code and reason
// If auth is provided, it will add authentication attributes and message integrity
func SendErrorResponse(conn net.Conn, transactionID [12]byte, code int, reason string, auth *StunAuthConfig) error {
	if conn == nil {
		return fmt.Errorf("invalid input: connection is required")
	}

	// Create error response
	response, err := CreateAuthenticatedErrorResponse(transactionID, code, reason, auth)
	if err != nil {
		return fmt.Errorf("failed to create error response: %w", err)
	}

	// Send response
	if _, err := conn.Write(response); err != nil {
		return fmt.Errorf("failed to send error response: %w", err)
	}

	return nil
}

// CreateResponseAttributes creates a combined set of attributes for a STUN response
// including XOR-MAPPED-ADDRESS, authentication attributes, and ICE attributes if provided
func CreateResponseAttributes(remoteAddr net.Addr, auth *StunAuthConfig, ice *IceAttributes) ([]byte, error) {
	if remoteAddr == nil {
		return nil, fmt.Errorf("invalid input: remote address is required")
	}

	// Create XOR-MAPPED-ADDRESS attribute
	xorMappedAddr, err := CreateXorMappedAddress(remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create XOR-MAPPED-ADDRESS: %w", err)
	}

	// Create response attributes
	var responseAttrs []byte
	responseAttrs = append(responseAttrs, xorMappedAddr...)

	// If authentication is required, add authentication attributes
	if auth != nil {
		// create a deep copy of the auth config
		responseAuth := *auth
		// remove the username attribute from the response
		// see RFC 8445 Section 7.2.2
		responseAuth.Username = ""
		authAttrs := CreateAuthAttributes(&responseAuth)
		if len(authAttrs) > 0 {
			responseAttrs = append(responseAttrs, authAttrs...)
		}
	}

	// Add ICE attributes if present
	if ice != nil {
		iceAttrs := CreateIceAttributes(ice)
		if len(iceAttrs) > 0 {
			responseAttrs = append(responseAttrs, iceAttrs...)
		}
	}

	return responseAttrs, nil
}

// CopyTransactionID copies the transaction ID from the source message to the destination message
// This updates both the Header.TransactionID and the raw bytes in the message
func CopyTransactionID(dst, src *StunMessage) {
	if dst == nil || src == nil {
		return
	}

	copy(dst.Header.TransactionID[:], src.Header.TransactionID[:])
	copy(dst.Raw[8:20], src.Header.TransactionID[:])
}

// CalculateFingerprint calculates the FINGERPRINT attribute value for a STUN message.
// The input should be the entire message up to (but excluding) the FINGERPRINT attribute itself.
func CalculateFingerprint(message []byte) uint32 {
	// Use IEEE CRC-32 and XOR with fingerprint XOR value per RFC 5389 Section 15.5
	crc := crc32.ChecksumIEEE(message)
	return crc ^ fingerprintXorValue
}

// CreateFingerprintAttribute creates the FINGERPRINT attribute for a given message.
// The input should be the entire message up to (but excluding) the FINGERPRINT attribute itself.
func CreateFingerprintAttribute(message []byte) []byte {
	// The value of the attribute is computed as the CRC-32 of the STUN message
	// up to (but excluding) the FINGERPRINT attribute itself
	fingerprint := CalculateFingerprint(message)
	attr := make([]byte, 8) // 4 bytes header + 4 bytes value
	binary.BigEndian.PutUint16(attr[0:2], attrFingerprint)
	binary.BigEndian.PutUint16(attr[2:4], 4)
	binary.BigEndian.PutUint32(attr[4:8], fingerprint)
	return attr
}

// AddFingerprint appends the FINGERPRINT attribute to a STUN message.
// It modifies the message in place by appending the FINGERPRINT attribute to the raw bytes.
func AddFingerprint(msg *StunMessage) error {
	if msg == nil {
		return fmt.Errorf("invalid input: message is required")
	}

	// The CRC used in the FINGERPRINT attribute
	// covers the length field from the STUN message header.  Therefore,
	// this value must be correct and include the CRC attribute as part of
	// the message length, prior to computation of the CRC.
	olen := binary.BigEndian.Uint16(msg.Raw[2:4])
	binary.BigEndian.PutUint16(msg.Raw[2:4], olen+8) // Add 8 bytes for FINGERPRINT

	// Create the complete FINGERPRINT attribute
	fingerprintAttr := CreateFingerprintAttribute(msg.Raw)

	// Append FINGERPRINT attribute to raw bytes
	msg.Raw = append(msg.Raw, fingerprintAttr...)
	msg.Attributes = append(msg.Attributes, fingerprintAttr...)

	msg.Header.Length = uint16(len(msg.Attributes))

	return nil
}

// calculatePadding returns the number of bytes needed to align the given length to 4 bytes.
// STUN attributes must be padded to a multiple of 4 bytes per RFC 5389.
func calculatePadding(length int) int {
	if length%4 == 0 {
		return 0
	}
	return 4 - (length % 4)
}
