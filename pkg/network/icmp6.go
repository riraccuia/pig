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

package network

import (
	"encoding/binary"

	"golang.org/x/net/ipv6"
)

// NewICMPv6EchoRequest builds an ICMPv6 Echo Request packet with the given id and sequence number.
func NewICMPv6EchoRequest(id, seq uint16, payloadLen int) (p []byte) {
	p = make([]byte, payloadLen)
	p[0] = uint8(ipv6.ICMPTypeEchoRequest)
	binary.BigEndian.PutUint16(p[4:6], id)
	binary.BigEndian.PutUint16(p[6:8], seq)
	return
}
