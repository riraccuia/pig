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
	"fmt"
)

const (
	// ICE STUN extension attribute types
	// https://datatracker.ietf.org/doc/html/rfc8445#section-20.1

	AttrICEPriority     uint16 = 0x0024
	AttrICEUseCandidate uint16 = 0x0025
	AttrICEControlled   uint16 = 0x8029
	AttrICEControlling  uint16 = 0x802A

	defaultIceTieBreaker uint64 = 0x12345678
)

// IceConfig represents ICE-specific STUN attributes.
type IceConfig struct {
	Priority       uint32
	UseCandidate   bool
	IceControlling uint64
	IceControlled  uint64
}

// IceAuth represents ICE-specific STUN credential semantics.
// ICE uses username fragments to build the STUN USERNAME attribute and
// selects different passwords for outgoing vs incoming requests.
type IceAuth struct {
	LocalUfrag     string
	LocalPassword  string
	RemoteUfrag    string
	RemotePassword string
}

// RequestAuth returns the generic STUN auth attributes for an outgoing ICE request.
func (a *IceAuth) RequestAuth() *AuthConfig {
	if a == nil {
		return nil
	}
	/*username := a.OutgoingUsername()
	if username == "" {
		return nil
	}*/
	return &AuthConfig{
		Username: a.OutgoingUsername(),
		Password: a.OutgoingRequestPassword(),
	}
}

// ExpectedAuth returns the generic STUN auth attributes expected from the peer.
func (a *IceAuth) ExpectedAuth() *AuthConfig {
	if a == nil {
		return nil
	}
	return &AuthConfig{
		Username: a.ExpectedIncomingUsername(),
		Password: a.IncomingRequestPassword(),
	}
}

// OutgoingUsername returns the ICE username value for an outgoing request.
func (a *IceAuth) OutgoingUsername() string {
	if a == nil || a.LocalUfrag == "" || a.RemoteUfrag == "" {
		return ""
	}
	return a.RemoteUfrag + ":" + a.LocalUfrag
}

// ExpectedIncomingUsername returns the ICE username value expected from the peer.
func (a *IceAuth) ExpectedIncomingUsername() string {
	if a == nil || a.LocalUfrag == "" || a.RemoteUfrag == "" {
		return ""
	}
	return a.LocalUfrag + ":" + a.RemoteUfrag
}

// OutgoingRequestPassword returns the password used to integrity-protect outgoing ICE requests.
func (a *IceAuth) OutgoingRequestPassword() string {
	if a == nil {
		return ""
	}
	return a.RemotePassword
}

// IncomingRequestPassword returns the password used to validate incoming ICE requests
// and integrity-protect the corresponding responses.
func (a *IceAuth) IncomingRequestPassword() string {
	if a == nil {
		return ""
	}
	return a.LocalPassword
}

// CreateIceAttributes creates ICE-specific attributes.
/*func CreateIceAttributes(ice *IceConfig) []byte {
	var attributes []byte

	if ice.Priority > 0 {
		attr := make([]byte, 8)
		binary.BigEndian.PutUint16(attr[0:2], AttrICEPriority)
		binary.BigEndian.PutUint16(attr[2:4], 4)
		binary.BigEndian.PutUint32(attr[4:8], ice.Priority)
		attributes = append(attributes, attr...)
	}

	if ice.UseCandidate {
		attr := make([]byte, 4)
		binary.BigEndian.PutUint16(attr[0:2], AttrICEUseCandidate)
		binary.BigEndian.PutUint16(attr[2:4], 0)
		attributes = append(attributes, attr...)
	}

	if ice.IceControlling > 0 {
		attr := make([]byte, 12)
		binary.BigEndian.PutUint16(attr[0:2], AttrICEControlling)
		binary.BigEndian.PutUint16(attr[2:4], 8)
		binary.BigEndian.PutUint64(attr[4:12], ice.IceControlling)
		attributes = append(attributes, attr...)
	}

	if ice.IceControlled > 0 {
		attr := make([]byte, 12)
		binary.BigEndian.PutUint16(attr[0:2], AttrICEControlled)
		binary.BigEndian.PutUint16(attr[2:4], 8)
		binary.BigEndian.PutUint64(attr[4:12], ice.IceControlled)
		attributes = append(attributes, attr...)
	}

	return attributes
}*/

// ParseIceAttributesFromMessage parses ICE-specific attributes from a STUN message.
func ParseIceAttributesFromMessage(message *Message) (*IceConfig, error) {
	ice := &IceConfig{}
	if attr, ok := message.FindAttribute(AttrICEPriority); ok {
		if p, ok := attr.(*ICEPriorityAttr); ok {
			ice.Priority = p.Value
		}
	}
	if _, ok := message.FindAttribute(AttrICEUseCandidate); ok {
		ice.UseCandidate = true
	}
	if attr, ok := message.FindAttribute(AttrICEControlling); ok {
		if c, ok := attr.(*ICEControllingAttr); ok {
			ice.IceControlling = c.Value
		}
	}
	if attr, ok := message.FindAttribute(AttrICEControlled); ok {
		if c, ok := attr.(*ICEControlledAttr); ok {
			ice.IceControlled = c.Value
		}
	}
	return ice, nil
}

// ParseIceAttributesFromBytes parses ICE-specific attributes from a byte slice.
func ParseIceAttributesFromBytes(data []byte) (*IceConfig, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("data too short for ICE attributes")
	}

	ice := &IceConfig{}
	offset := 0

	for offset < len(data) {
		if offset+4 > len(data) {
			break
		}

		attrType := binary.BigEndian.Uint16(data[offset:])
		attrLen := binary.BigEndian.Uint16(data[offset+2:])
		offset += 4

		if offset+int(attrLen) > len(data) {
			break
		}

		value := data[offset : offset+int(attrLen)]

		switch attrType {
		case AttrICEPriority:
			if len(value) == 4 {
				ice.Priority = binary.BigEndian.Uint32(value)
			}
		case AttrICEUseCandidate:
			ice.UseCandidate = true
		case AttrICEControlling:
			if len(value) == 8 {
				ice.IceControlling = binary.BigEndian.Uint64(value)
			}
		case AttrICEControlled:
			if len(value) == 8 {
				ice.IceControlled = binary.BigEndian.Uint64(value)
			}
		}

		offset += int(attrLen)
		padding := calculatePadding(int(attrLen))
		offset += padding
	}

	return ice, nil
}
