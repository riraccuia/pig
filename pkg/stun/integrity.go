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
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
)

// VerifyMessageIntegrity verifies the MESSAGE-INTEGRITY attribute (HMAC-SHA1) in a STUN message.
// It is equivalent to calling VerifyMessageIntegrityWithHash with AttrMessageIntegrity and sha1.New.
func (msg *Message) VerifyMessageIntegrity(password string) (bool, error) {
	return msg.VerifyMessageIntegrityWithHash(password, AttrMessageIntegrity, sha1.New)
}

// VerifyMessageIntegritySHA256 verifies the MESSAGE-INTEGRITY-SHA256 attribute (HMAC-SHA256) in a STUN message.
// It is equivalent to calling VerifyMessageIntegrityWithHash with AttrMessageIntegritySHA256 and sha256.New.
func (msg *Message) VerifyMessageIntegritySHA256(password string) (bool, error) {
	return msg.VerifyMessageIntegrityWithHash(password, AttrMessageIntegritySHA256, sha256.New)
}

// AddMessageIntegrity adds the MESSAGE-INTEGRITY attribute (HMAC-SHA1) to a STUN message.
// It is equivalent to calling AddMessageIntegrityWithHash with AttrMessageIntegrity and sha1.New.
func (msg *Message) AddMessageIntegrity(password string) error {
	return msg.AddMessageIntegrityWithHash(password, AttrMessageIntegrity, sha1.New)
}

// AddMessageIntegritySHA256 adds the MESSAGE-INTEGRITY-SHA256 attribute (HMAC-SHA256) to a STUN message.
// It is equivalent to calling AddMessageIntegrityWithHash with AttrMessageIntegritySHA256 and sha256.New.
func (msg *Message) AddMessageIntegritySHA256(password string) error {
	return msg.AddMessageIntegrityWithHash(password, AttrMessageIntegritySHA256, sha256.New)
}

// CalculateShortTermMessageIntegrity calculates the HMAC-SHA1 message integrity
// according to RFC 8489 Section 14.5 (MESSAGE-INTEGRITY). The given password is
// processed using the OpaqueString profile. Returns 20 bytes.
func CalculateShortTermMessageIntegrity(message []byte, password string) []byte {
	return CalculateShortTermMessageIntegrityWithHash(message, password, AttrMessageIntegrity, sha1.New)
}

// CalculateShortTermMessageIntegritySHA256 calculates the HMAC-SHA256 message
// integrity according to RFC 8489 Section 14.6 (MESSAGE-INTEGRITY-SHA256). The
// given password is processed using the OpaqueString profile. Returns 32 bytes.
func CalculateShortTermMessageIntegritySHA256(message []byte, password string) []byte {
	return CalculateShortTermMessageIntegrityWithHash(message, password, AttrMessageIntegritySHA256, sha256.New)
}

// VerifyMessageIntegrityWithHash verifies the given message-integrity attribute in a STUN message.
// It searches for attrType, computes expected integrity using newHash, and compares.
func (msg *Message) VerifyMessageIntegrityWithHash(password string, attrType uint16, newHash func() hash.Hash) (bool, error) {
	if password == "" {
		return false, errors.New("password is required for message integrity verification")
	}
	if newHash == nil {
		return false, errors.New("hash function is required")
	}

	messageIntegrity, ok := msg.FindAttribute(attrType)
	if !ok {
		return false, errors.New("message integrity attribute not found")
	}
	messageIntegrityAttr, ok := messageIntegrity.(*MessageIntegrityAttr)
	if !ok {
		return false, errors.New("message integrity attribute is not a MessageIntegrityAttr")
	}

	expected := CalculateShortTermMessageIntegrityWithHash(msg.Raw.Bytes(), password, attrType, newHash)
	if expected == nil {
		return false, errors.New("failed to calculate message integrity")
	}

	return bytes.Equal(messageIntegrityAttr.Value[:], expected), nil
}

// AddMessageIntegrityWithHash adds a given message-integrity attribute to a STUN message.
// It handles the two-phase integrity calculation and uses attrType and newHash for the algorithm.
func (msg *Message) AddMessageIntegrityWithHash(password string, attrType uint16, newHash func() hash.Hash) error {
	if msg == nil || password == "" {
		return fmt.Errorf("invalid input: message and password are required")
	}
	if newHash == nil {
		return fmt.Errorf("hash function is required")
	}

	hashSize := newHash().Size()
	integrityAttr := NewMessageIntegrityAttr([20]byte{})
	if integrityAttr == nil {
		return fmt.Errorf("failed to create message integrity attribute")
	}

	if err := msg.AppendAttribute(integrityAttr); err != nil {
		return fmt.Errorf("failed to add message integrity attribute: %w", err)
	}

	finalIntegrity := CalculateShortTermMessageIntegrityWithHash(msg.Raw.Bytes(), password, attrType, newHash)
	if finalIntegrity == nil {
		return fmt.Errorf("failed to calculate final message integrity")
	}
	if len(finalIntegrity) != hashSize {
		return fmt.Errorf("illegal message integrity length: %d", len(finalIntegrity))
	}

	copy(integrityAttr.Value[:], finalIntegrity)
	raw := msg.Raw.Bytes()
	copy(raw[len(raw)-hashSize:], finalIntegrity)
	//msg.raw = make([]byte, msg.SerializeLen())
	//return msg.SerializeTo(msg.raw)
	return nil
}

// CalculateShortTermMessageIntegrityWithHash computes HMAC-based message integrity for STUN
// per RFC 8489. It searches for attrType in the message, truncates at that position,
// and computes HMAC using OpaqueString(password) as the key. newHash supplies the hash
// algorithm; its Size() determines the attribute value length.
// This method could be used to implement new message integrity algorithms, other than the currenly
// supported ones  by the spec (HMAC-SHA1 and HMAC-SHA256).
func CalculateShortTermMessageIntegrityWithHash(message []byte, password string, attrType uint16, newHash func() hash.Hash) []byte {
	if password == "" || len(message) < 20 || newHash == nil {
		return nil
	}

	hashFunc := newHash()
	const tlvHeaderSize = 4
	attrSize := tlvHeaderSize + hashFunc.Size()

	var messageLen int
	for i := 20; i < len(message); {
		if i+4 > len(message) {
			break
		}
		at := binary.BigEndian.Uint16(message[i : i+2])
		attrLen := binary.BigEndian.Uint16(message[i+2 : i+4])
		if at == attrType {
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

	msgCopy := make([]byte, messageLen)
	copy(msgCopy, message[:messageLen])
	adjustedLength := uint16(messageLen - 20 + attrSize)
	binary.BigEndian.PutUint16(msgCopy[2:4], adjustedLength)

	key := []byte(OpaqueString(password))
	h := hmac.New(newHash, key)
	h.Write(msgCopy)
	return h.Sum(nil)
}

// createMessageIntegrityAttr creates a message-integrity attribute with the given type and value.
/*func createMessageIntegrityAttr(attrType uint16, integrity []byte) []byte {
	if integrity == nil {
		return nil
	}
	attr := make([]byte, 4+len(integrity))
	binary.BigEndian.PutUint16(attr[0:2], attrType)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(integrity)))
	copy(attr[4:], integrity)
	padding := calculatePadding(len(integrity))
	if padding > 0 {
		attr = append(attr, make([]byte, padding)...)
	}
	return attr
}

// CreateMessageIntegrityAttribute creates a MESSAGE-INTEGRITY attribute from the given integrity value
func CreateMessageIntegrityAttribute(integrity []byte) []byte {
	return createMessageIntegrityAttr(AttrMessageIntegrity, integrity)
}*/

// ValidateShortTermIntegrity validates a Binding request against expected short-term
// credentials per RFC 8489 Section 9.1. It compares the USERNAME (after OpaqueString
// processing) and verifies MESSAGE-INTEGRITY using the expected password.
// Returns nil if validation passes. When expected is nil or expected.Password is empty,
// returns nil (no auth required). Callers are responsible for sending 401 on error.
func ValidateShortTermIntegrity(request *Message, expected *AuthConfig) error {
	if expected == nil || expected.Password == "" {
		return nil
	}
	if request == nil {
		return fmt.Errorf("binding request is required")
	}

	gotUsername := ""
	rAuth, err := request.GetAuthParams()
	if err != nil {
		return fmt.Errorf("failed to get auth parameters from request: %w", err)
	}
	if rAuth != nil {
		gotUsername = rAuth.Username
	}
	opaqueGot := OpaqueString(gotUsername)
	opaqueExpected := OpaqueString(expected.Username)

	if opaqueGot == "" {
		return fmt.Errorf("username missing or invalid")
	}
	if opaqueGot != opaqueExpected {
		return fmt.Errorf("username mismatch")
	}

	valid, err := request.VerifyMessageIntegrity(expected.Password)
	if err != nil {
		return fmt.Errorf("message integrity verification failed: %w", err)
	}
	if !valid {
		return fmt.Errorf("message integrity verification failed")
	}

	return nil
}
