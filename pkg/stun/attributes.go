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
)

const (
	// STUN attributes

	// Comprehension-required range (0x0000-0x7FFF)
	AttrMappedAddress          uint16 = 0x0001
	AttrUsername               uint16 = 0x0006
	AttrMessageIntegrity       uint16 = 0x0008
	AttrMessageIntegritySHA256 uint16 = 0x001C
	AttrErrorCode              uint16 = 0x0009
	AttrRealm                  uint16 = 0x0014
	AttrNonce                  uint16 = 0x0015
	AttrXorMappedAddress       uint16 = 0x0020
	// Comprehension-optional range (0x8000-0xFFFF)
	AttrFingerprint uint16 = 0x8028
	// RFC 5780 attributes
	AttrChangeRequest uint16 = 0x0003 // RFC 5780 Section 7.2
	AttrOtherAddress  uint16 = 0x802c // RFC 5780 Section 7.4

	TLVPrefixLength = 4
)

const (
	// RFC 5780 Section 7.2 CHANGE-REQUEST flag A: request response from alternate IP.
	changeIPFlag uint32 = 0x00000004
	// RFC 5780 Section 7.2 CHANGE-REQUEST flag B: request response from alternate port.
	changePortFlag uint32 = 0x00000002
)

// Attribute is the generalized interface for all STUN attributes.
type Attribute interface {
	Serializable
	// DecodeFromBytes decodes the input bytes into the attribute.
	DecodeFromBytes(b []byte) error
	// GetType returns the type of the attribute.
	GetType() uint16
	// IsICE reports whether the attribute is an ICE extension attribute.
	IsICE() bool
}

// DecodeAttributes decodes the input bytes as raw attribute data into a slice of Attribute.
// This is assumed to be the raw attribute data, not the entire message.
func DecodeAttributes(data []byte) ([]Attribute, error) {
	var attrs []Attribute
	offset := 0

	for offset < len(data) {
		if offset+4 > len(data) {
			break
		}
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		factory, ok := typeRegistry[attrType]
		if !ok {
			//return nil, fmt.Errorf("unknown attribute type: 0x%04x", attrType)
			// skip unknown attributes
			attrLen := binary.BigEndian.Uint16(data[offset+2 : offset+4])
			offset += int(attrLen) + 4
			continue
		}
		attr := factory()

		if err := attr.DecodeFromBytes(data[offset:]); err != nil {
			return nil, fmt.Errorf("parse attribute 0x%04x: %w", attrType, err)
		}
		attrs = append(attrs, attr)
		offset += attr.SerializeLen()
	}

	return attrs, nil
}

// attrSerializedSize returns the total bytes needed to serialize an attribute
// with the given value length (TLV prefix + value + padding).
func attrSerializedSize(valueLen uint16) int {
	return int(TLVPrefixLength) + int(valueLen) + calculatePadding(int(valueLen))
}

// UsernameAttr implements Attribute for USERNAME (0x0006).
// Implements the [Attribute] interface.
type UsernameAttr struct {
	Value string
}

func (a *UsernameAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 4 {
		return errors.New("username attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrUsername {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected USERNAME", attrType)
	}
	if int(attrLen) > len(b)-4 {
		return errors.New("username attribute length exceeds buffer")
	}
	a.Value = string(b[4 : 4+attrLen])
	return nil
}

func (a *UsernameAttr) GetType() uint16 { return AttrUsername }
func (a *UsernameAttr) SerializeLen() int {
	return attrSerializedSize(uint16(len(a.Value)))
}
func (a *UsernameAttr) IsICE() bool { return false }

// NewUsernameAttr creates a USERNAME attribute.
func NewUsernameAttr(value string) *UsernameAttr {
	return &UsernameAttr{Value: value}
}
func (a *UsernameAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	valueBytes := []byte(a.Value)
	attrLen := len(valueBytes)
	// paddedLen := attrLen + calculatePadding(attrLen)
	binary.BigEndian.PutUint16(b[0:2], AttrUsername)
	binary.BigEndian.PutUint16(b[2:4], uint16(attrLen))
	copy(b[4:], valueBytes)
	clear(b[4+attrLen:]) // clear padded bytes
	/*for i := 4 + attrLen; i < 4+paddedLen; i++ {
		b[i] = 0
	}*/
	return nil
}

// RealmAttr implements Attribute for REALM (0x0014).
// Implements the [Attribute] interface.
type RealmAttr struct {
	Value string
}

func (a *RealmAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 4 {
		return errors.New("realm attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrRealm {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected REALM", attrType)
	}
	if int(attrLen) > len(b)-4 {
		return errors.New("realm attribute length exceeds buffer")
	}
	a.Value = string(b[4 : 4+attrLen])
	return nil
}

func (a *RealmAttr) GetType() uint16 { return AttrRealm }
func (a *RealmAttr) SerializeLen() int {
	return attrSerializedSize(uint16(len(a.Value)))
}
func (a *RealmAttr) IsICE() bool { return false }

// NewRealmAttr creates a REALM attribute.
func NewRealmAttr(value string) *RealmAttr {
	return &RealmAttr{Value: value}
}
func (a *RealmAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	valueBytes := []byte(a.Value)
	attrLen := len(valueBytes)
	// paddedLen := attrLen + calculatePadding(attrLen)
	binary.BigEndian.PutUint16(b[0:2], AttrRealm)
	binary.BigEndian.PutUint16(b[2:4], uint16(attrLen))
	copy(b[4:], valueBytes)
	clear(b[4+attrLen:]) // clear padded bytes
	/*for i := 4 + attrLen; i < 4+paddedLen; i++ {
		b[i] = 0
	}*/
	return nil
}

// NonceAttr implements Attribute for NONCE (0x0015).
// Implements the [Attribute] interface.
type NonceAttr struct {
	Value string
}

func (a *NonceAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 4 {
		return errors.New("nonce attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrNonce {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected NONCE", attrType)
	}
	if int(attrLen) > len(b)-4 {
		return errors.New("nonce attribute length exceeds buffer")
	}
	a.Value = string(b[4 : 4+attrLen])
	return nil
}

func (a *NonceAttr) GetType() uint16 { return AttrNonce }
func (a *NonceAttr) SerializeLen() int {
	return attrSerializedSize(uint16(len(a.Value)))
}
func (a *NonceAttr) IsICE() bool { return false }

// NewNonceAttr creates a NONCE attribute.
func NewNonceAttr(value string) *NonceAttr {
	return &NonceAttr{Value: value}
}
func (a *NonceAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	valueBytes := []byte(a.Value)
	attrLen := len(valueBytes)
	//paddedLen := attrLen + calculatePadding(attrLen)
	binary.BigEndian.PutUint16(b[0:2], AttrNonce)
	binary.BigEndian.PutUint16(b[2:4], uint16(attrLen))
	copy(b[4:], valueBytes)
	clear(b[4+attrLen:]) // clear padded bytes
	/*for i := 4 + attrLen; i < 4+paddedLen; i++ {
		b[i] = 0
	}*/
	return nil
}

// MessageIntegrityAttr implements Attribute for MESSAGE-INTEGRITY (0x0008).
// Value is the 20-byte HMAC-SHA1.
// Implements the [Attribute] interface.
type MessageIntegrityAttr struct {
	Value [20]byte
}

func (a *MessageIntegrityAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 24 {
		return errors.New("message integrity attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrMessageIntegrity {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected MESSAGE-INTEGRITY", attrType)
	}
	if attrLen != 20 {
		return fmt.Errorf("invalid message integrity length: %d", attrLen)
	}
	copy(a.Value[:], b[4:24])
	return nil
}

func (a *MessageIntegrityAttr) GetType() uint16 { return AttrMessageIntegrity }
func (a *MessageIntegrityAttr) SerializeLen() int {
	return attrSerializedSize(20)
}
func (a *MessageIntegrityAttr) IsICE() bool { return false }

// NewMessageIntegrityAttr creates a MESSAGE-INTEGRITY attribute.
func NewMessageIntegrityAttr(value [20]byte) *MessageIntegrityAttr {
	return &MessageIntegrityAttr{Value: value}
}
func (a *MessageIntegrityAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	binary.BigEndian.PutUint16(b[0:2], AttrMessageIntegrity)
	binary.BigEndian.PutUint16(b[2:4], 20)
	copy(b[4:], a.Value[:])
	return nil
}

// MessageIntegritySHA256Attr implements Attribute for MESSAGE-INTEGRITY-SHA256 (0x001C).
// Value is the 32-byte HMAC-SHA256.
// Implements the [Attribute] interface.
type MessageIntegritySHA256Attr struct {
	Value [32]byte
}

func (a *MessageIntegritySHA256Attr) DecodeFromBytes(b []byte) error {
	if len(b) < 36 {
		return errors.New("message integrity sha256 attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrMessageIntegritySHA256 {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected MESSAGE-INTEGRITY-SHA256", attrType)
	}
	if attrLen != 32 {
		return fmt.Errorf("invalid message integrity sha256 length: %d", attrLen)
	}
	copy(a.Value[:], b[4:36])
	return nil
}

func (a *MessageIntegritySHA256Attr) GetType() uint16 { return AttrMessageIntegritySHA256 }
func (a *MessageIntegritySHA256Attr) SerializeLen() int {
	return attrSerializedSize(32)
}
func (a *MessageIntegritySHA256Attr) IsICE() bool { return false }

// NewMessageIntegritySHA256Attr creates a MESSAGE-INTEGRITY-SHA256 attribute.
func NewMessageIntegritySHA256Attr(value [32]byte) *MessageIntegritySHA256Attr {
	return &MessageIntegritySHA256Attr{Value: value}
}
func (a *MessageIntegritySHA256Attr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	binary.BigEndian.PutUint16(b[0:2], AttrMessageIntegritySHA256)
	binary.BigEndian.PutUint16(b[2:4], 32)
	copy(b[4:], a.Value[:])
	return nil
}

// ErrorCodeAttr implements Attribute for ERROR-CODE (0x0009).
// Code is the numeric error code (e.g. 401), Reason is the human-readable string.
// Implements the [Attribute] interface.
type ErrorCodeAttr struct {
	Code   int
	Reason string
}

func (a *ErrorCodeAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 8 {
		return errors.New("error code attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrErrorCode {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected ERROR-CODE", attrType)
	}
	if int(attrLen) < 4 {
		return errors.New("error code value too short")
	}
	value := b[4:]
	// Matches CreateErrorResponse: value[4]=reserved, value[5]=class, value[6]=number, value[7]=reserved
	class := int(value[1])
	number := int(value[2])
	a.Code = class*100 + number
	if int(attrLen) > 4 {
		a.Reason = string(value[4 : 4+int(attrLen)-4])
	} else {
		a.Reason = ""
	}
	return nil
}

func (a *ErrorCodeAttr) GetType() uint16 { return AttrErrorCode }
func (a *ErrorCodeAttr) SerializeLen() int {
	return attrSerializedSize(uint16(4 + len(a.Reason)))
}
func (a *ErrorCodeAttr) IsICE() bool { return false }

// NewErrorCodeAttr creates an ERROR-CODE attribute.
func NewErrorCodeAttr(code int, reason string) *ErrorCodeAttr {
	return &ErrorCodeAttr{Code: code, Reason: reason}
}
func (a *ErrorCodeAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	valueLen := uint16(4 + len(a.Reason))
	// paddedLen := int(valueLen) + calculatePadding(int(valueLen))
	binary.BigEndian.PutUint16(b[0:2], AttrErrorCode)
	binary.BigEndian.PutUint16(b[2:4], valueLen)
	b[4] = 0
	b[5] = byte(a.Code / 100)
	b[6] = byte(a.Code % 100)
	b[7] = 0
	copy(b[8:], []byte(a.Reason))
	clear(b[8+len(a.Reason):]) // clear padded bytes
	/*for i := 8 + len(a.Reason); i < 4+paddedLen; i++ {
		b[i] = 0
	}*/
	return nil
}

// MappedAddressAttr implements Attribute for MAPPED-ADDRESS (0x0001).
// Value holds the raw attribute value (family, port, IP).
// Implements the [Attribute] interface.
type MappedAddressAttr struct {
	Value []byte
}

func (a *MappedAddressAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 4 {
		return errors.New("mapped address attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrMappedAddress {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected MAPPED-ADDRESS", attrType)
	}
	if attrLen != 8 && attrLen != 20 {
		return fmt.Errorf("invalid mapped address length: %d", attrLen)
	}
	if int(attrLen) > len(b)-4 {
		return errors.New("mapped address length exceeds buffer")
	}
	a.Value = make([]byte, attrLen)
	copy(a.Value, b[4:4+attrLen])
	return nil
}

func (a *MappedAddressAttr) GetType() uint16 { return AttrMappedAddress }
func (a *MappedAddressAttr) SerializeLen() int {
	return attrSerializedSize(uint16(len(a.Value)))
}
func (a *MappedAddressAttr) IsICE() bool { return false }
func (a *MappedAddressAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	valueLen := uint16(len(a.Value))
	binary.BigEndian.PutUint16(b[0:2], AttrMappedAddress)
	binary.BigEndian.PutUint16(b[2:4], valueLen)
	copy(b[4:], a.Value)
	clear(b[4+len(a.Value):]) // clear padded bytes
	return nil
}

func (a *MappedAddressAttr) DecodeMappedAddress() (net.IP, int, error) {
	// decode the mapped address, ipv4 or ipv6
	family := a.Value[1]
	port := binary.BigEndian.Uint16(a.Value[2:4])
	switch family {
	case 0x01:
		return net.IP(a.Value[4:8]), int(port), nil
	case 0x02:
		return net.IP(a.Value[4:20]), int(port), nil
	default:
		return nil, 0, fmt.Errorf("unsupported address family: %d", family)
	}
}

// XorMappedAddressAttr implements Attribute for XOR-MAPPED-ADDRESS (0x0020).
// Value holds the raw attribute value (reserved, family, xor'd port, xor'd IP).
// Implements the [Attribute] interface.
type XorMappedAddressAttr struct {
	Value []byte
}

func (a *XorMappedAddressAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 4 {
		return errors.New("xor mapped address attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrXorMappedAddress {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected XOR-MAPPED-ADDRESS", attrType)
	}
	if attrLen != 8 && attrLen != 20 {
		return fmt.Errorf("invalid xor mapped address length: %d", attrLen)
	}
	if int(attrLen) > len(b)-4 {
		return errors.New("xor mapped address length exceeds buffer")
	}
	a.Value = make([]byte, attrLen)
	copy(a.Value, b[4:4+attrLen])
	return nil
}

func (a *XorMappedAddressAttr) GetType() uint16 { return AttrXorMappedAddress }
func (a *XorMappedAddressAttr) SerializeLen() int {
	return attrSerializedSize(uint16(len(a.Value)))
}
func (a *XorMappedAddressAttr) IsICE() bool { return false }
func (a *XorMappedAddressAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	valueLen := uint16(len(a.Value))
	binary.BigEndian.PutUint16(b[0:2], AttrXorMappedAddress)
	binary.BigEndian.PutUint16(b[2:4], valueLen)
	copy(b[4:], a.Value)
	clear(b[4+len(a.Value):]) // clear padded bytes
	/*padded := int(valueLen) + calculatePadding(int(valueLen))
	for i := 4 + len(a.Value); i < 4+padded; i++ {
		b[i] = 0
	}*/
	return nil
}

// NewXorMappedAddressAttr creates an XOR-MAPPED-ADDRESS attribute using CreateXorMappedAddress.
func NewXorMappedAddressAttr(addr net.Addr, txID [12]byte) (*XorMappedAddressAttr, error) {
	attrBytes, err := CreateXorMappedAddress(addr, txID)
	if err != nil {
		return nil, err
	}
	a := &XorMappedAddressAttr{}
	if err := a.DecodeFromBytes(attrBytes); err != nil {
		return nil, err
	}
	return a, nil
}

// DecodeXorMappedAddress decodes Value (raw XOR'd bytes) into IP and port using txID.
func (a *XorMappedAddressAttr) DecodeXorMappedAddress(txID [12]byte) (net.IP, int, error) {
	v := a.Value
	if len(v) < 8 {
		return nil, 0, errors.New("xor mapped address value too short")
	}
	family := v[1]
	port := int(binary.BigEndian.Uint16(v[2:4]) ^ uint16(MagicCookie>>16))
	switch family {
	case 0x01:
		if len(v) < 8 {
			return nil, 0, errors.New("xor mapped address IPv4 value too short")
		}
		ip := make(net.IP, 4)
		for i := 0; i < 4; i++ {
			ip[i] = v[4+i] ^ byte(MagicCookie>>((3-i)*8))
		}
		return ip, port, nil
	case 0x02:
		if len(v) < 20 {
			return nil, 0, errors.New("xor mapped address IPv6 value too short")
		}
		ip := make(net.IP, 16)
		for i := 0; i < 4; i++ {
			ip[i] = v[4+i] ^ byte(MagicCookie>>((3-i)*8))
		}
		for i := 4; i < 16; i++ {
			ip[i] = v[4+i] ^ txID[i-4]
		}
		return ip, port, nil
	default:
		return nil, 0, fmt.Errorf("unsupported address family: %d", family)
	}
}

// FingerprintAttr implements Attribute for FINGERPRINT (0x8028).
// Value is the 4-byte CRC-32.
// Implements the [Attribute] interface.
type FingerprintAttr struct {
	Value uint32
}

func (a *FingerprintAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 8 {
		return errors.New("fingerprint attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrFingerprint {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected FINGERPRINT", attrType)
	}
	if attrLen != 4 {
		return fmt.Errorf("invalid fingerprint length: %d", attrLen)
	}
	a.Value = binary.BigEndian.Uint32(b[4:8])
	return nil
}

func (a *FingerprintAttr) GetType() uint16 { return AttrFingerprint }
func (a *FingerprintAttr) SerializeLen() int {
	return attrSerializedSize(4)
}
func (a *FingerprintAttr) IsICE() bool { return false }
func (a *FingerprintAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	binary.BigEndian.PutUint16(b[0:2], AttrFingerprint)
	binary.BigEndian.PutUint16(b[2:4], 4)
	binary.BigEndian.PutUint32(b[4:8], a.Value)
	return nil
}

// NewFingerprintAttr creates a FINGERPRINT attribute.
// The input should be the entire message up to (but excluding) the FINGERPRINT attribute itself.
// Per RFC 5389, the CRC covers the message with the header Length field including the
// FINGERPRINT attribute (8 bytes), so we adjust the Length before hashing and restore it afterwards.
func NewFingerprintAttr(message []byte) *FingerprintAttr {
	return &FingerprintAttr{
		Value: CalculateFingerprint(message),
	}
}

// ICEPriorityAttr implements Attribute for PRIORITY (0x0024).
// Implements the [Attribute] interface.
type ICEPriorityAttr struct {
	Value uint32
}

func (a *ICEPriorityAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 8 {
		return errors.New("ice priority attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrICEPriority {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected PRIORITY", attrType)
	}
	if attrLen != 4 {
		return fmt.Errorf("invalid ice priority length: %d", attrLen)
	}
	a.Value = binary.BigEndian.Uint32(b[4:8])
	return nil
}

func (a *ICEPriorityAttr) GetType() uint16 { return AttrICEPriority }
func (a *ICEPriorityAttr) SerializeLen() int {
	return attrSerializedSize(4)
}
func (a *ICEPriorityAttr) IsICE() bool { return true }
func (a *ICEPriorityAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	binary.BigEndian.PutUint16(b[0:2], AttrICEPriority)
	binary.BigEndian.PutUint16(b[2:4], 4)
	binary.BigEndian.PutUint32(b[4:8], a.Value)
	return nil
}

// NewICEPriorityAttr creates a PRIORITY attribute.
func NewICEPriorityAttr(value uint32) *ICEPriorityAttr {
	return &ICEPriorityAttr{Value: value}
}

// ICEUseCandidateAttr implements Attribute for USE-CANDIDATE (0x0025).
// Implements the [Attribute] interface.
type ICEUseCandidateAttr struct{}

func (a *ICEUseCandidateAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 4 {
		return errors.New("ice use candidate attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrICEUseCandidate {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected USE-CANDIDATE", attrType)
	}
	if attrLen != 0 {
		return fmt.Errorf("invalid ice use candidate length: %d", attrLen)
	}
	return nil
}

func (a *ICEUseCandidateAttr) GetType() uint16 { return AttrICEUseCandidate }
func (a *ICEUseCandidateAttr) SerializeLen() int {
	return attrSerializedSize(0)
}
func (a *ICEUseCandidateAttr) IsICE() bool { return true }
func (a *ICEUseCandidateAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	binary.BigEndian.PutUint16(b[0:2], AttrICEUseCandidate)
	binary.BigEndian.PutUint16(b[2:4], 0)
	return nil
}

// NewICEUseCandidateAttr creates a USE-CANDIDATE attribute.
func NewICEUseCandidateAttr() *ICEUseCandidateAttr {
	return &ICEUseCandidateAttr{}
}

// ICEControllingAttr implements Attribute for ICE-CONTROLLING (0x802A).
// Implements the [Attribute] interface.
type ICEControllingAttr struct {
	Value uint64
}

func (a *ICEControllingAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 12 {
		return errors.New("ice controlling attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrICEControlling {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected ICE-CONTROLLING", attrType)
	}
	if attrLen != 8 {
		return fmt.Errorf("invalid ice controlling length: %d", attrLen)
	}
	a.Value = binary.BigEndian.Uint64(b[4:12])
	return nil
}

func (a *ICEControllingAttr) GetType() uint16 { return AttrICEControlling }
func (a *ICEControllingAttr) SerializeLen() int {
	return attrSerializedSize(8)
}
func (a *ICEControllingAttr) IsICE() bool { return true }
func (a *ICEControllingAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	binary.BigEndian.PutUint16(b[0:2], AttrICEControlling)
	binary.BigEndian.PutUint16(b[2:4], 8)
	binary.BigEndian.PutUint64(b[4:12], a.Value)
	return nil
}

// NewICEControllingAttr creates an ICE-CONTROLLING attribute.
func NewICEControllingAttr(value uint64) *ICEControllingAttr {
	return &ICEControllingAttr{Value: value}
}

// ICEControlledAttr implements Attribute for ICE-CONTROLLED (0x8029).
// Implements the [Attribute] interface.
type ICEControlledAttr struct {
	Value uint64
}

func (a *ICEControlledAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 12 {
		return errors.New("ice controlled attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrICEControlled {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected ICE-CONTROLLED", attrType)
	}
	if attrLen != 8 {
		return fmt.Errorf("invalid ice controlled length: %d", attrLen)
	}
	a.Value = binary.BigEndian.Uint64(b[4:12])
	return nil
}

func (a *ICEControlledAttr) GetType() uint16 { return AttrICEControlled }
func (a *ICEControlledAttr) SerializeLen() int {
	return attrSerializedSize(8)
}
func (a *ICEControlledAttr) IsICE() bool { return true }
func (a *ICEControlledAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	binary.BigEndian.PutUint16(b[0:2], AttrICEControlled)
	binary.BigEndian.PutUint16(b[2:4], 8)
	binary.BigEndian.PutUint64(b[4:12], a.Value)
	return nil
}

// NewICEControlledAttr creates an ICE-CONTROLLED attribute.
func NewICEControlledAttr(value uint64) *ICEControlledAttr {
	return &ICEControlledAttr{Value: value}
}

// UnknownAttr holds an attribute type not in the registry for round-trip.
// Implements the [Attribute] interface.
type UnknownAttr struct {
	Type  uint16
	Value []byte
}

func (a *UnknownAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 4 {
		return errors.New("unknown attribute too short")
	}
	a.Type = binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if int(attrLen) > len(b)-4 {
		return errors.New("unknown attribute length exceeds buffer")
	}
	a.Value = make([]byte, attrLen)
	copy(a.Value, b[4:4+attrLen])
	return nil
}

func (a *UnknownAttr) GetType() uint16 { return a.Type }
func (a *UnknownAttr) SerializeLen() int {
	return attrSerializedSize(uint16(len(a.Value)))
}
func (a *UnknownAttr) IsICE() bool { return false }
func (a *UnknownAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	valueLen := uint16(len(a.Value))
	// paddedLen := int(valueLen) + calculatePadding(int(valueLen))
	binary.BigEndian.PutUint16(b[0:2], a.Type)
	binary.BigEndian.PutUint16(b[2:4], valueLen)
	copy(b[4:], a.Value)
	clear(b[4+len(a.Value):]) // clear padded bytes
	/*for i := 4 + len(a.Value); i < 4+paddedLen; i++ {
		b[i] = 0
	}*/
	return nil
}

// ChangeRequestAttr implements Attribute for CHANGE-REQUEST (0x0003).
// The attribute carries "change IP" (A) and "change port" (B) flags that
// instruct the server to send the Binding Response from an alternate source
// address and/or port (RFC 5780 Section 7.2).
// Implements the [Attribute] interface.
type ChangeRequestAttr struct {
	Flags uint32
}

func (a *ChangeRequestAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 4 {
		return errors.New("change-request attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrChangeRequest {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected CHANGE-REQUEST", attrType)
	}
	if attrLen != 4 {
		return fmt.Errorf("invalid change-request length: %d", attrLen)
	}
	if int(attrLen) > len(b)-4 {
		return errors.New("change-request attribute length exceeds buffer")
	}
	a.Flags = binary.BigEndian.Uint32(b[4 : 4+attrLen])
	return nil
}

func (a *ChangeRequestAttr) GetType() uint16 { return AttrChangeRequest }
func (a *ChangeRequestAttr) SerializeLen() int {
	return attrSerializedSize(4)
}
func (a *ChangeRequestAttr) IsICE() bool { return false }

// NewChangeRequestAttr creates a CHANGE-REQUEST attribute with the given flags.
// Use changePortFlag for filtering test III and changeIPAndPortFlag for
// filtering test II (RFC 5780 Section 4.4).
func NewChangeRequestAttr(flags uint32) *ChangeRequestAttr {
	return &ChangeRequestAttr{Flags: flags}
}

func (a *ChangeRequestAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	binary.BigEndian.PutUint16(b[0:2], AttrChangeRequest)
	binary.BigEndian.PutUint16(b[2:4], 4)
	binary.BigEndian.PutUint32(b[4:8], a.Flags)
	return nil
}

// OtherAddressAttr implements Attribute for OTHER-ADDRESS (0x802c).
// Value holds the raw transport address (family, port, IP) the server would use
// when both CHANGE-REQUEST flags are set (RFC 5780 Section 7.4). The wire
// format matches MAPPED-ADDRESS (RFC 5780 Section 7.1).
// Implements the [Attribute] interface.
type OtherAddressAttr struct {
	Value []byte
}

func (a *OtherAddressAttr) DecodeFromBytes(b []byte) error {
	if len(b) < 4 {
		return errors.New("other-address attribute too short")
	}
	attrType := binary.BigEndian.Uint16(b[0:2])
	attrLen := binary.BigEndian.Uint16(b[2:4])
	if attrType != AttrOtherAddress {
		return fmt.Errorf("wrong attribute type: got 0x%04x, expected OTHER-ADDRESS", attrType)
	}
	if attrLen != 8 && attrLen != 20 {
		return fmt.Errorf("invalid other-address length: %d", attrLen)
	}
	if int(attrLen) > len(b)-4 {
		return errors.New("other-address attribute length exceeds buffer")
	}
	a.Value = make([]byte, attrLen)
	copy(a.Value, b[4:4+attrLen])
	return nil
}

func (a *OtherAddressAttr) GetType() uint16 { return AttrOtherAddress }
func (a *OtherAddressAttr) SerializeLen() int {
	return attrSerializedSize(uint16(len(a.Value)))
}
func (a *OtherAddressAttr) IsICE() bool { return false }

func (a *OtherAddressAttr) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(a.SerializeLen())
	valueLen := uint16(len(a.Value))
	binary.BigEndian.PutUint16(b[0:2], AttrOtherAddress)
	binary.BigEndian.PutUint16(b[2:4], valueLen)
	copy(b[4:], a.Value)
	clear(b[4+len(a.Value):])
	return nil
}

// DecodeOtherAddress decodes Value into IP and port.
func (a *OtherAddressAttr) DecodeOtherAddress() (net.IP, int, error) {
	if len(a.Value) < 4 {
		return nil, 0, errors.New("other-address value too short")
	}
	family := a.Value[1]
	port := binary.BigEndian.Uint16(a.Value[2:4])
	switch family {
	case 0x01:
		if len(a.Value) < 8 {
			return nil, 0, errors.New("other-address IPv4 value too short")
		}
		return net.IP(a.Value[4:8]), int(port), nil
	case 0x02:
		if len(a.Value) < 20 {
			return nil, 0, errors.New("other-address IPv6 value too short")
		}
		return net.IP(a.Value[4:20]), int(port), nil
	default:
		return nil, 0, fmt.Errorf("unsupported address family: %d", family)
	}
}

// typeRegistry maps attribute type to constructor for parseAttributes.
var typeRegistry = map[uint16]func() Attribute{
	AttrMappedAddress:          func() Attribute { return &MappedAddressAttr{} },
	AttrUsername:               func() Attribute { return &UsernameAttr{} },
	AttrMessageIntegrity:       func() Attribute { return &MessageIntegrityAttr{} },
	AttrMessageIntegritySHA256: func() Attribute { return &MessageIntegritySHA256Attr{} },
	AttrErrorCode:              func() Attribute { return &ErrorCodeAttr{} },
	AttrRealm:                  func() Attribute { return &RealmAttr{} },
	AttrNonce:                  func() Attribute { return &NonceAttr{} },
	AttrXorMappedAddress:       func() Attribute { return &XorMappedAddressAttr{} },
	AttrFingerprint:            func() Attribute { return &FingerprintAttr{} },
	AttrICEPriority:            func() Attribute { return &ICEPriorityAttr{} },
	AttrICEUseCandidate:        func() Attribute { return &ICEUseCandidateAttr{} },
	AttrICEControlled:          func() Attribute { return &ICEControlledAttr{} },
	AttrICEControlling:         func() Attribute { return &ICEControllingAttr{} },
	AttrChangeRequest:          func() Attribute { return &ChangeRequestAttr{} },
	AttrOtherAddress:           func() Attribute { return &OtherAddressAttr{} },
}
