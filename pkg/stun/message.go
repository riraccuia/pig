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
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"slices"
)

// Message represents a STUN message with its header and attributes.
// Properties are exported but should not be modified directly, unless you know what you are doing.
type Message struct {
	// Header is the header of the message.
	Header Header
	// Attributes is the list of attributes in the message
	// in the order they appear when serialized.
	Attributes []Attribute
	// Raw is the raw bytes of the message.
	Raw Buffer
	// fingerprint is a flag indicating that serialization methods like SerializeTo and WriteTo
	// should compute and add a FINGERPRINT attribute to the message before serializing it.
	fingerprint bool
}

// WithFingerprint sets the message to compute and add a FINGERPRINT attribute to the message
// before serializing it or writing it to a writer.
func (msg *Message) WithFingerprint() *Message {
	msg.fingerprint = true
	return msg
}

// DecodeMessage parses a raw STUN message into its components.
// This is equivalent to calling msg.DecodeFromBytes(data) on a new Message.
func DecodeMessage(data []byte) (*Message, error) {
	msg := &Message{}
	if err := msg.DecodeFromBytes(data); err != nil {
		return nil, err
	}
	return msg, nil
}

// NewMessage creates a new STUN message with the given type and attributes (random txID).
func NewMessage(msgType uint16, attrs []Attribute) (*Message, error) {
	txID := [12]byte{}
	if _, err := rand.Read(txID[:]); err != nil {
		return nil, fmt.Errorf("failed to generate transaction ID: %w", err)
	}
	return NewMessageWithTransactionID(msgType, attrs, txID)
}

// NewMessageWithTransactionID creates a new STUN message with the given type, attributes, and transaction ID.
func NewMessageWithTransactionID(msgType uint16, attrs []Attribute, txID [12]byte) (*Message, error) {
	msg := &Message{
		Header: NewHeader(msgType, txID),
	}

	if err := msg.Header.SerializeTo(&msg.Raw); err != nil {
		return nil, fmt.Errorf("failed to serialize message: %w", err)
	}

	for _, attr := range attrs {
		if err := msg.AppendAttribute(attr); err != nil {
			return nil, fmt.Errorf("failed to add attribute: %w", err)
		}
	}

	return msg, nil
}

// DecodeFromBytes decodes the input bytes into the STUN message.
func (msg *Message) DecodeFromBytes(data []byte) error {
	if err := msg.Header.DecodeFromBytes(data); err != nil {
		return err
	}
	if len(data) < 20+int(msg.Header.Length) {
		return fmt.Errorf("STUN message truncated: expected %d bytes, got %d", 20+int(msg.Header.Length), len(data))
	}
	attrs, err := DecodeAttributes(data[20 : 20+int(msg.Header.Length)])
	if err != nil {
		return err
	}
	msg.Attributes = attrs
	msg.Raw = *NewBuffer(data[:20+int(msg.Header.Length)])
	return nil
}

// SerializeLen returns the total serialized length of the message.
func (msg *Message) SerializeLen() int {
	n := 20
	hasFingerprint := false
	for _, attr := range msg.Attributes {
		if attr.GetType() == AttrFingerprint {
			hasFingerprint = true
			continue
		}
		n += attr.SerializeLen()
	}
	if msg.fingerprint && !hasFingerprint {
		n += 8
	}
	return n
}

// Validate validates the message header.
// TODO: Add more validation.
func (msg *Message) Validate(opts *BindingOptions) error {
	if err := msg.Header.Validate(); err != nil {
		return err
	}

	if opts != nil && opts.Auth != nil {
		if err := ValidateShortTermIntegrity(msg, opts.Auth); err != nil {
			return err
		}
	}

	if opts != nil && opts.RequireFingerprint && !msg.VerifyFingerprint() {
		return fmt.Errorf("invalid STUN message: fingerprint verification failed")
	}

	return nil
}

// SerializeTo writes the message using SerializeBuffer.
func (msg *Message) SerializeTo(sb SerializeBuffer) error {
	if msg.fingerprint {
		if err := msg.AddFingerprint(); err != nil {
			return err
		}
	}
	if err := msg.Header.SerializeTo(sb); err != nil {
		return err
	}
	for _, attr := range msg.Attributes {
		if err := attr.SerializeTo(sb); err != nil {
			return err
		}
	}
	return nil
}

// SerializeToRaw clears the internal Raw buffer and serializes the full message to it.
// You should call this method after manually modifying any of the message's attributes.
// It is equivalent to calling SerializeTo(&msg.Raw).
func (msg *Message) SerializeToRaw() error {
	msg.Raw.Reset()
	return msg.SerializeTo(&msg.Raw)
}

// WriteTo writes the message to a writer, e.g. a socket (net.Conn) or file.
func (msg *Message) WriteTo(w io.Writer) (int64, error) {
	if msg.fingerprint {
		if err := msg.AddFingerprint(); err != nil {
			return 0, err
		}
	}
	n, err := w.Write(msg.Raw.Bytes())
	return int64(n), err
}

// FindAttribute returns the first attribute with the given type.
func (msg *Message) FindAttribute(attrType uint16) (Attribute, bool) {
	i := slices.IndexFunc(msg.Attributes, func(a Attribute) bool { return a.GetType() == attrType })
	if i < 0 {
		return nil, false
	}
	return msg.Attributes[i], true
}

// AppendAttribute appends one or more attributes to the message.
// The method enforces the requirement that you cannot append attributes after a FINGERPRINT attribute.
// You can only append MESSAGE-INTEGRITY-SHA256 or FINGERPRINT attributes after a MESSAGE-INTEGRITY attribute.
// You can only append the FINGERPRINT attribute after a MESSAGE-INTEGRITY-SHA256 attribute.
func (msg *Message) AppendAttribute(attrs ...Attribute) error {
	for _, attr := range attrs {
		if err := msg.appendAttribute(attr); err != nil {
			return err
		}
	}
	return nil
}

// appendAttribute appends an attribute to the message only if it is valid to do so.
func (msg *Message) appendAttribute(attr Attribute) error {
	if len(msg.Attributes) == 0 {
		return msg.unsafeAppendAttribute(attr)
	}
	switch msg.Attributes[len(msg.Attributes)-1].GetType() {
	case AttrFingerprint:
		return fmt.Errorf("cannot append attribute after FINGERPRINT attribute")
	case AttrMessageIntegrity:
		if attr.GetType() == AttrMessageIntegritySHA256 {
			break
		}
		if attr.GetType() == AttrFingerprint {
			break
		}
		return fmt.Errorf("cannot append attribute after MESSAGE-INTEGRITY attribute")
	case AttrMessageIntegritySHA256:
		if attr.GetType() == AttrFingerprint {
			break
		}
		return fmt.Errorf("cannot append attribute after MESSAGE-INTEGRITY-SHA256 attribute")
	}
	return msg.unsafeAppendAttribute(attr)
}

// unsafeAppendAttribute appends an attribute to the message without checking the last attribute.
func (msg *Message) unsafeAppendAttribute(attr Attribute) error {
	msg.Attributes = append(msg.Attributes, attr)
	attrLen := attr.SerializeLen()
	msg.Header.Length += uint16(attrLen)
	if err := attr.SerializeTo(&msg.Raw); err != nil {
		return fmt.Errorf("failed to serialize attribute: %w", err)
	}
	raw := msg.Raw.Bytes()
	binary.BigEndian.PutUint16(raw[2:4], msg.Header.Length)
	return nil
}

// ParseError extracts error code and reason from a STUN message.
func (msg *Message) ParseError() (ErrorCodeAttr, error) {
	attr, ok := msg.FindAttribute(AttrErrorCode)
	if !ok {
		return ErrorCodeAttr{}, errors.New("error code attribute not found")
	}
	ec, ok := attr.(*ErrorCodeAttr)
	if !ok {
		return ErrorCodeAttr{}, errors.New("error code attribute not found")
	}
	return *ec, nil
}

// MappedAddrPort extracts the mapped address and port from a STUN response.
func (msg *Message) MappedAddrPort() (net.IP, int, error) {
	var (
		attr Attribute
		ok   bool
	)
	// first try to find a XOR-MAPPED-ADDRESS attribute
	attr, ok = msg.FindAttribute(AttrXorMappedAddress)
	if !ok {
		// if not found, check for a MAPPED-ADDRESS attribute
		attr, ok = msg.FindAttribute(AttrMappedAddress)
	}
	if !ok {
		return nil, 0, errors.New("mapped address not found")
	}
	switch attr.GetType() {
	case AttrXorMappedAddress:
		xa, ok := attr.(*XorMappedAddressAttr)
		if !ok {
			return nil, 0, errors.New("mapped address not found")
		}
		return xa.DecodeXorMappedAddress(msg.Header.TransactionID)
	case AttrMappedAddress:
		ma, ok := attr.(*MappedAddressAttr)
		if !ok {
			return nil, 0, errors.New("mapped address not found")
		}
		return ma.DecodeMappedAddress()
	default:
		return nil, 0, fmt.Errorf("unsupported mapped address type: 0x%04x", attr.GetType())
	}
	/*attr, ok := msg.FindAttribute(AttrXorMappedAddress)
	if !ok {
		return nil, 0, errors.New("mapped address not found")
	}
	xa, ok := attr.(*XorMappedAddressAttr)
	if !ok {
		return nil, 0, errors.New("mapped address not found")
	}
	return xa.DecodeXorMappedAddress(msg.Header.TransactionID)*/
}

// GetAuthParams extracts authentication attributes (Username, Realm, Nonce) from a STUN message.
func (msg *Message) GetAuthParams() (*AuthConfig, error) {
	auth := &AuthConfig{}
	if attr, ok := msg.FindAttribute(AttrUsername); ok {
		if u, ok := attr.(*UsernameAttr); ok {
			auth.Username = u.Value
		}
	}
	if attr, ok := msg.FindAttribute(AttrRealm); ok {
		if r, ok := attr.(*RealmAttr); ok {
			auth.Realm = r.Value
		}
	}
	if attr, ok := msg.FindAttribute(AttrNonce); ok {
		if n, ok := attr.(*NonceAttr); ok {
			auth.Nonce = n.Value
		}
	}
	return auth, nil
}
