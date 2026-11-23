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
	"net/netip"
)

// TransportChecksumValid reports whether the TCP or UDP checksum over the
// IPv4 or IPv6 pseudo-header is correct (RFC 9293 §3.1, RFC 768, RFC 8200 §8.1).
// A valid transport payload folds to 0xffff. UDP's IPv4-zero / IPv6-mandatory
// rules are left to the caller.
func TransportChecksumValid(proto uint8, src, dst netip.Addr, transport []byte) bool {
	sum := addWords(0, src.AsSlice())             // source address
	sum = addWords(sum, dst.AsSlice())            // destination address
	sum += uint64(proto) + uint64(len(transport)) // protocol + length
	sum = addWords(sum, transport)                // header and payload
	return fold(sum) == 0xffff                    // valid ones' complement sum
}

// addWords accumulates network-order 16-bit words into a one's-complement
// sum (RFC 1071), eight bytes at a time.
func addWords(sum uint64, b []byte) uint64 {
	for len(b) >= 8 {
		sum += uint64(binary.BigEndian.Uint32(b[0:4])) // first 32-bit word
		sum += uint64(binary.BigEndian.Uint32(b[4:8])) // second 32-bit word
		b = b[8:]                                      // advance past the pair
	}
	for len(b) >= 2 {
		sum += uint64(binary.BigEndian.Uint16(b[:2])) // leftover 16-bit word
		b = b[2:]                                     // advance past it
	}
	if len(b) == 1 {
		sum += uint64(b[0]) << 8 // odd trailing byte, high half
	}
	return sum
}

func fold(sum uint64) uint16 {
	sum = sum>>32 + sum&0xffffffff // 64 → 33 bits
	sum = sum>>16 + sum&0xffff     // 33 → 17 bits
	sum = sum>>16 + sum&0xffff     // final end-around carry
	return uint16(sum)
}

func (p IPv4Packet) UpdateChecksum() {
	if p.TotalLength() > len(p) {
		return // truncated packet
	}
	p.updateIPChecksum() // IP header first
	switch p.Protocol() {
	case ProtocolICMP:
		p.updateICMPChecksum()
	case ProtocolTCP:
		p.updateTCPChecksum()
	case ProtocolUDP:
		p.updateUDPChecksum()
	}
}

func (p IPv4Packet) updateIPChecksum() {
	p[10], p[11] = 0, 0                              // clear field
	sum := ^fold(addWords(0, p[:p.PayloadOffset()])) // header only
	p[10] = byte(sum >> 8)                           // high byte
	p[11] = byte(sum)                                // low byte
}

func (p IPv4Packet) updateTCPChecksum() {
	offset := p.PayloadOffset()                  // start of TCP
	tcpLen := p.TotalLength() - offset           // TCP length
	p[offset+16], p[offset+17] = 0, 0            // clear field
	sum := p.pseudoHeaderSum(tcpLen)             // pseudo-header
	sum = addWords(sum, p[offset:offset+tcpLen]) // TCP segment
	csum := ^fold(sum)                           // one's complement
	p[offset+16] = byte(csum >> 8)               // high byte
	p[offset+17] = byte(csum)                    // low byte
}

func (p IPv4Packet) updateUDPChecksum() {
	offset := p.PayloadOffset() // start of UDP
	if len(p) < offset+8 {
		return // too short for a UDP header
	}
	udpLen := int(binary.BigEndian.Uint16(p[offset+4 : offset+6])) // length field
	if offset+udpLen > len(p) {
		return // length exceeds packet
	}
	p[offset+6], p[offset+7] = 0, 0              // clear field
	sum := p.pseudoHeaderSum(udpLen)             // pseudo-header
	sum = addWords(sum, p[offset:offset+udpLen]) // UDP datagram
	csum := ^fold(sum)                           // one's complement
	if csum == 0 {
		csum = 0xffff // 0 means "none", so use all-ones
	}
	p[offset+6] = byte(csum >> 8) // high byte
	p[offset+7] = byte(csum)      // low byte
}

func (p IPv4Packet) updateICMPChecksum() {
	offset := p.PayloadOffset()                          // start of ICMP
	icmpLen := p.TotalLength() - offset                  // ICMP length
	p[offset+2], p[offset+3] = 0, 0                      // clear field
	csum := ^fold(addWords(0, p[offset:offset+icmpLen])) // no pseudo-header
	p[offset+2] = byte(csum >> 8)                        // high byte
	p[offset+3] = byte(csum)                             // low byte
}

func (p IPv4Packet) pseudoHeaderSum(transportLen int) uint64 {
	sum := addWords(0, p[12:20])               // src + dst
	sum += uint64(p[9]) + uint64(transportLen) // protocol + length
	return sum
}
