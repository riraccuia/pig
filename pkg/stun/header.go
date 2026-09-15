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
)

// Header represents the STUN message header.
type Header struct {
	Type          uint16
	Length        uint16
	MagicCookie   uint32
	TransactionID [12]byte
}

// NewHeader returns a Header with the given type, attribute length, and transaction ID.
func NewHeader(msgType uint16, txID [12]byte) Header {
	return Header{
		Type:          msgType,
		Length:        0,
		MagicCookie:   MagicCookie,
		TransactionID: txID,
	}
}

// Validate validates the basic STUN header properties.
func (h *Header) Validate() error {
	if h == nil {
		return errors.New("nil header")
	}
	if h.Type&0xC000 != 0 {
		return fmt.Errorf("invalid type: top two bits must be zero")
	}
	if h.MagicCookie != MagicCookie {
		return fmt.Errorf("invalid magic cookie")
	}
	if h.Length%4 != 0 {
		return fmt.Errorf("invalid length: must be 32-bit aligned")
	}
	return nil
}

// DecodeFromBytes decodes the input bytes into the STUN header.
func (h *Header) DecodeFromBytes(data []byte) error {
	if len(data) < 20 {
		return fmt.Errorf("STUN message too short: %d bytes", len(data))
	}

	h.Type = binary.BigEndian.Uint16(data[0:2])
	h.Length = binary.BigEndian.Uint16(data[2:4])
	h.MagicCookie = binary.BigEndian.Uint32(data[4:8])
	copy(h.TransactionID[:], data[8:20])

	return nil
}

// SerializeLen returns the length of the serialized header.
func (h *Header) SerializeLen() int {
	return 20
}

// SerializeTo serializes the header to a SerializeBuffer.
func (h *Header) SerializeTo(sb SerializeBuffer) error {
	b := sb.Append(20)
	binary.BigEndian.PutUint16(b[0:2], h.Type)
	binary.BigEndian.PutUint16(b[2:4], h.Length)
	binary.BigEndian.PutUint32(b[4:8], h.MagicCookie)
	copy(b[8:20], h.TransactionID[:])
	return nil
}
