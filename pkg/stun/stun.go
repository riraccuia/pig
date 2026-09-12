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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"time"
)

var ErrParseMessage = errors.New("failed to parse STUN message")

// Serializable is the interface that represents a serializable object.
type Serializable interface {
	// SerializeLen returns the length of the serialized object over the wire.
	SerializeLen() int
	// SerializeTo serializes the object to a SerializeBuffer.
	SerializeTo(sb SerializeBuffer) error
}

// AuthConfig represents generic STUN authentication configuration.
type AuthConfig struct {
	Username string
	Password string
	Realm    string
	Nonce    string
}

const (
	// STUN Constants (RFC 8489, RFC 5389, RFC 3489)

	// STUN message types
	MsgTypeBindingRequest       uint16 = 0x0001
	MsgTypeBindingResponse      uint16 = 0x0101
	MsgTypeBindingErrorResponse uint16 = 0x0111
	// FINGERPRINT XOR value (RFC 5389 Section 15.5)
	FingerprintXorValue uint32 = 0x5354554e

	// STUN magic cookie value
	MagicCookie uint32 = 0x2112A442

	stunTimeout = 3 * time.Second
)

// Method is the 12-bit STUN method encoding defined in RFC 8489 Section 5.
type Method uint16

// Class is the 2-bit STUN class encoding defined in RFC 8489 Section 5.
type Class uint16

const (
	MethodBinding Method = 0x0001
)

const (
	ClassRequest         Class = 0x0000
	ClassIndication      Class = 0x0001
	ClassSuccessResponse Class = 0x0002
	ClassErrorResponse   Class = 0x0003
)

var StunClassStrings = map[Class]string{
	ClassRequest:         "request",
	ClassIndication:      "indication",
	ClassSuccessResponse: "success response",
	ClassErrorResponse:   "error response",
}

var StunMethodStrings = map[Method]string{
	MethodBinding: "binding",
}

func (c Class) String() string {
	// handle unknown class
	if str, ok := StunClassStrings[c]; ok {
		return str
	}
	return fmt.Sprintf("unknown class: 0x%04x", uint16(c))
}

func (m Method) String() string {
	// handle unknown method
	if str, ok := StunMethodStrings[m]; ok {
		return str
	}
	return fmt.Sprintf("unknown method: 0x%04x", uint16(m))
}

// MessageMethod extracts the STUN method from a raw STUN message type.
// The masks and shifts intentionally mirror RFC 8489 Appendix A.
func MessageMethod(msgType uint16) Method {
	return Method(
		((msgType & 0x3E00) >> 2) |
			((msgType & 0x00E0) >> 1) |
			(msgType & 0x000F),
	)
}

// MessageClass extracts the STUN class from a raw STUN message type.
// The masks and shifts intentionally mirror RFC 8489 Appendix A.
func MessageClass(msgType uint16) Class {
	return Class(
		((msgType & 0x0100) >> 7) |
			((msgType & 0x0010) >> 4),
	)
}

// IsRequestType reports whether the raw STUN message type is a request.
func IsRequestType(msgType uint16) bool {
	return msgType&0x0110 == 0x0000
}

// IsIndicationType reports whether the raw STUN message type is an indication.
func IsIndicationType(msgType uint16) bool {
	return msgType&0x0110 == 0x0010
}

// IsSuccessResponseType reports whether the raw STUN message type is a success response.
func IsSuccessResponseType(msgType uint16) bool {
	return msgType&0x0110 == 0x0100
}

// IsErrorResponseType reports whether the raw STUN message type is an error response.
func IsErrorResponseType(msgType uint16) bool {
	return msgType&0x0110 == 0x0110
}

// EncodeMessageType encodes a STUN method and class into the wire value.
// The masks and shifts intentionally mirror RFC 8489 Appendix A.
func EncodeMessageType(method Method, class Class) uint16 {
	m := uint16(method)
	c := uint16(class)

	return ((m & 0x1F80) << 2) |
		((m & 0x0070) << 1) |
		(m & 0x000F) |
		((c & 0x0002) << 7) |
		((c & 0x0001) << 4)
}

// ValidateMethodAndClass validates that a raw STUN message type matches the
// expected method and one of the allowed classes.
func ValidateMethodAndClass(msgType uint16, expectedMethod Method, allowedClasses ...Class) error {
	method := MessageMethod(msgType)
	if method != expectedMethod {
		return fmt.Errorf("unsupported STUN method: got %s want %s", method, expectedMethod)
	}

	class := MessageClass(msgType)
	for _, allowedClass := range allowedClasses {
		if class == allowedClass {
			return nil
		}
	}

	if len(allowedClasses) == 0 {
		return fmt.Errorf("unsupported STUN class %s for method %s", class, expectedMethod)
	}

	return fmt.Errorf("unsupported STUN class %s for method %s", class, expectedMethod)
}

// CreateXorMappedAddress creates a full, raw XOR-MAPPED-ADDRESS attribute
// for the given address and transaction ID.
func CreateXorMappedAddress(addr net.Addr, txID [12]byte) ([]byte, error) {
	var (
		//host    string
		ip   net.IP
		port int
		err  error
	)

	switch a := addr.(type) {
	case *net.IPAddr:
		ip = a.IP
		port = 0
	case *net.TCPAddr:
		ip = a.IP
		port = a.Port
	case *net.UDPAddr:
		ip = a.IP
		port = a.Port
	default:
		var host, portStr string
		host, portStr, err = net.SplitHostPort(addr.String())
		ip = net.ParseIP(host)
		port, err = strconv.Atoi(portStr)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse address: %w", err)
	}

	if ip == nil {
		return nil, fmt.Errorf("invalid IP address: %s", addr.String())
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
	xorPort := uint16(port) ^ uint16(MagicCookie>>16)
	binary.BigEndian.PutUint16(xorMappedAddr[2:4], xorPort)

	// XOR IP address with magic cookie
	magicCookieBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(magicCookieBytes, MagicCookie)

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
			xorMappedAddr[4+i] = addrBytes[i] ^ txID[i-4]
		}
	}

	// Create attribute header
	attr := make([]byte, 4+attrLength)
	binary.BigEndian.PutUint16(attr[0:2], AttrXorMappedAddress)
	binary.BigEndian.PutUint16(attr[2:4], attrLength)
	copy(attr[4:], xorMappedAddr)

	return attr, nil
}

// CreateErrorMessage creates a STUN error message.
func CreateErrorMessage(txID [12]byte, code int, reason string) (*Message, error) {
	attrs := []Attribute{NewErrorCodeAttr(code, reason)}
	return NewMessageWithTransactionID(MsgTypeBindingErrorResponse, attrs, txID)
}

// CreateAuthenticatedErrorMessage creates a STUN error response with authentication attributes.
// Where authentication is not required, call CreateErrorMessage instead.
// Per RFC 8445, Username is omitted from error responses.
func CreateAuthenticatedErrorMessage(txID [12]byte, code int, reason string, auth *AuthConfig) (*Message, error) {
	msg, err := CreateErrorMessage(txID, code, reason)
	if err != nil {
		return nil, fmt.Errorf("failed to create error message: %w", err)
	}
	if auth == nil {
		return nil, errors.New("authentication configuration is required")
	}
	if auth.Realm != "" {
		msg.AppendAttribute(NewRealmAttr(auth.Realm))
	}
	if auth.Nonce != "" {
		msg.AppendAttribute(NewNonceAttr(auth.Nonce))
	}
	return msg.WithFingerprint(), nil
}

// SendErrorResponse creates and sends a STUN error response with the given error code and reason.
// If auth is provided, it will add authentication attributes.
func SendErrorResponse(conn net.Conn, transactionID [12]byte, code int, reason string, auth *AuthConfig) error {
	if conn == nil {
		return fmt.Errorf("invalid input: connection is required")
	}
	msg, err := CreateAuthenticatedErrorMessage(transactionID, code, reason, auth)
	if err != nil {
		return fmt.Errorf("failed to create error response: %w", err)
	}
	if _, err := msg.WriteTo(conn); err != nil {
		return fmt.Errorf("failed to send error response: %w", err)
	}
	return nil
}
