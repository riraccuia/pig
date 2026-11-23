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

func (p IPv6Packet) UpdateChecksum() {
	protocol, offset, transportLen, ok := p.transportHeader()
	if !ok {
		return // no usable transport header
	}
	switch protocol {
	case ipProtoTCP:
		p.updateTCPChecksum()
	case ipProtoUDP:
		p.updateUDPChecksum()
	case ipProtoICMPv6:
		p.updateICMPv6Checksum(offset, transportLen)
	}
}

func (p IPv6Packet) updateTCPChecksum() {
	protocol, offset, tcpLen, ok := p.transportHeader()
	if !ok || protocol != ipProtoTCP || len(p) < offset+20 {
		return // missing or truncated TCP
	}
	p[offset+16], p[offset+17] = 0, 0            // clear field
	sum := p.pseudoHeaderSum(ipProtoTCP, tcpLen) // pseudo-header
	sum = addWords(sum, p[offset:offset+tcpLen]) // TCP segment
	csum := ^fold(sum)                           // one's complement
	p[offset+16] = byte(csum >> 8)               // high byte
	p[offset+17] = byte(csum)                    // low byte
}

func (p IPv6Packet) updateUDPChecksum() {
	protocol, offset, transportLen, ok := p.transportHeader()
	if !ok || protocol != ipProtoUDP || len(p) < offset+8 {
		return // missing or truncated UDP
	}
	udpLen := int(uint16(p[offset+4])<<8 | uint16(p[offset+5])) // length field
	if udpLen == 0 {
		udpLen = transportLen // jumbogram: length is zero on the wire
	}
	if udpLen < 8 || offset+udpLen > len(p) {
		return // invalid length
	}
	p[offset+6], p[offset+7] = 0, 0              // clear field
	sum := p.pseudoHeaderSum(ipProtoUDP, udpLen) // pseudo-header
	sum = addWords(sum, p[offset:offset+udpLen]) // UDP datagram
	csum := ^fold(sum)                           // one's complement
	if csum == 0 {
		csum = 0xffff // 0 means "none", so use all-ones
	}
	p[offset+6] = byte(csum >> 8) // high byte
	p[offset+7] = byte(csum)      // low byte
}

func (p IPv6Packet) updateICMPv6Checksum(offset, icmpLen int) {
	if len(p) < offset+4 || offset+icmpLen > len(p) || icmpLen < 4 {
		return // truncated ICMPv6
	}
	p[offset+2], p[offset+3] = 0, 0                  // clear field
	sum := p.pseudoHeaderSum(ipProtoICMPv6, icmpLen) // pseudo-header required
	sum = addWords(sum, p[offset:offset+icmpLen])    // ICMPv6 message
	csum := ^fold(sum)                               // one's complement
	p[offset+2] = byte(csum >> 8)                    // high byte
	p[offset+3] = byte(csum)                         // low byte
}

func (p IPv6Packet) pseudoHeaderSum(nextHeader uint8, upperLayerLen int) uint64 {
	sum := addWords(0, p[8:40])                       // src + dst
	sum += uint64(upperLayerLen) + uint64(nextHeader) // length + next header
	return sum
}
