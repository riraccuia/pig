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

const (
	DSCP_MARK_ADAPTER_SNAT = byte(8)
	DSCP_MARK_MASQ_SNAT    = byte(16)
	DSCP_MARK_ADAPTER_DNAT = byte(24)
	DSCP_MARK_MASQ_DNAT    = byte(32)
)

func (p IPv4Packet) Mark(flag byte) {
	// Preserve ECN bits (lower 2 bits) and set DSCP to 0x3F (upper 6 bits)
	// 0x3F << 2 = 0xFC (11111100 in binary)
	// p[1] & 0x03 preserves the ECN bits (00000011)
	// (0x3F << 2) | (p[1] & 0x03) sets DSCP to 0x3F while keeping ECN
	p[1] = (flag << 2) | (p[1] & 0b00000011)
}

func (p IPv4Packet) GetMark() byte {
	// Check if DSCP value (upper 6 bits) is set to 0x3F
	// p[1] >> 2 extracts the DSCP field (upper 6 bits)
	// 0x3F is 63 in decimal, which is the expected DSCP value
	return (p[1] >> 2)
}

func (p IPv4Packet) ClearMark() {
	// remove any dscp mark except for ECN
	p[1] = p[1] & 0b00000011
}
