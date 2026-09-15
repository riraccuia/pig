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
	"hash/crc32"
)

// CalculateFingerprint calculates the FINGERPRINT attribute value for a STUN message.
// The input should be the entire message up to (but excluding) the FINGERPRINT attribute itself.
// Per RFC 5389, the CRC covers the message with the header Length field including the
// FINGERPRINT attribute (8 bytes), so we adjust the Length before hashing and restore it afterwards.
func CalculateFingerprint(message []byte) uint32 {
	// Adjust the Length field to include the FINGERPRINT attribute (8 bytes)
	attrLen := uint16(len(message)-20) + 8
	// Store the original Length field
	origLen := binary.BigEndian.Uint16(message[2:4])
	// Update the Length field
	binary.BigEndian.PutUint16(message[2:4], attrLen)
	// Calculate the fingerprint
	// Use IEEE CRC-32 and XOR with fingerprint XOR value per RFC 5389 Section 15.5
	//dummy := make([]byte, 8)
	//binary.BigEndian.PutUint16(dummy[0:2], AttrFingerprint)
	//binary.BigEndian.PutUint16(dummy[2:4], 4)
	crc := crc32.ChecksumIEEE(message)
	// Restore the original Length field
	binary.BigEndian.PutUint16(message[2:4], origLen)
	return crc ^ FingerprintXorValue
}

// AddFingerprint appends the FINGERPRINT attribute to a STUN message.
func (msg *Message) AddFingerprint() error {
	if len(msg.Attributes) == 0 {
		attr := NewFingerprintAttr(msg.Raw.Bytes())
		return msg.appendAttribute(attr)
	}
	// Check if the last attribute is a FINGERPRINT attribute and remove it if it is
	la := msg.Attributes[len(msg.Attributes)-1]
	if la.GetType() == AttrFingerprint {
		// Remove the FINGERPRINT attribute
		msg.Attributes = msg.Attributes[:len(msg.Attributes)-1]
		msg.Header.Length -= uint16(la.SerializeLen())
		// Update the raw bytes
		msg.Raw = *NewBuffer(msg.Raw.Bytes()[:msg.Raw.Len()-la.SerializeLen()])
	}
	attr := NewFingerprintAttr(msg.Raw.Bytes())
	return msg.appendAttribute(attr)
}

// VerifyFingerprint verifies the FINGERPRINT attribute in a STUN message.
func (msg *Message) VerifyFingerprint() bool {
	attr, ok := msg.FindAttribute(AttrFingerprint)
	if !ok {
		return false
	}
	fp, ok := attr.(*FingerprintAttr)
	if !ok {
		return false
	}
	raw := msg.Raw.Bytes()
	if len(raw) < 8 {
		return false
	}
	expected := CalculateFingerprint(raw[:len(raw)-8])
	return fp.Value == expected
}
