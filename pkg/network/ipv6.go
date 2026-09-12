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
	"net"

	"golang.org/x/net/ipv6"
)

type IPv6Packet []byte

const (
	ipProtoHopByHop = 0
	ipProtoTCP      = 6
	ipProtoUDP      = 17
	ipProtoRouting  = 43
	ipProtoFragment = 44
	ipProtoESP      = 50
	ipProtoAH       = 51
	ipProtoICMPv6   = 58
	ipProtoNoNext   = 59
	ipProtoDestOpts = 60
	ipProtoMobility = 135
	ipProtoHIP      = 139
	ipProtoShim6    = 140
)

func (p IPv6Packet) Bytes() []byte {
	return p[:]
}

func (p IPv6Packet) Version() int {
	return int(p[0] >> 4)
}

func (p IPv6Packet) SetSourceIP(ip net.IP) {
	copy(p[8:24], ip.To16())
}

func (p IPv6Packet) SetDestinationIP(ip net.IP) {
	copy(p[24:40], ip.To16())
}

func (p IPv6Packet) TotalLength() int {
	return int(uint16(p[5])|uint16(p[4])<<8) + ipv6.HeaderLen
}

func (p IPv6Packet) TotalLengthLE() uint16 {
	return binary.NativeEndian.Uint16(p[4:6])
}

func (p IPv6Packet) DestinationIP() net.IP {
	return net.IP(p[24:40])
}

func (p IPv6Packet) SourceIP() net.IP {
	return net.IP(p[8:24])
}

func (p IPv6Packet) Protocol() uint8 {
	protocol, _, _, ok := p.transportHeader()
	if !ok {
		if len(p) <= 6 {
			return 0
		}
		return p[6]
	}
	return protocol
}

func (p IPv6Packet) SourcePort() uint16 {
	protocol, offset, _, ok := p.transportHeader()
	if !ok {
		return 0
	}
	if protocol != ipProtoTCP && protocol != ipProtoUDP {
		return 0
	}
	if len(p) < offset+4 {
		return 0
	}
	return uint16(p[offset+1]) | uint16(p[offset])<<8
}

func (p IPv6Packet) DestinationPort() uint16 {
	protocol, offset, _, ok := p.transportHeader()
	if !ok {
		return 0
	}
	if protocol != ipProtoTCP && protocol != ipProtoUDP {
		return 0
	}
	if len(p) < offset+4 {
		return 0
	}
	return uint16(p[offset+3]) | uint16(p[offset+2])<<8
}

func (p IPv6Packet) PayloadOffset() int {
	return ipv6.HeaderLen
}

func (p IPv6Packet) transportHeader() (protocol uint8, offset int, transportLen int, ok bool) {
	if len(p) < ipv6.HeaderLen {
		return 0, 0, 0, false
	}

	payloadLen := int(uint16(p[5]) | uint16(p[4])<<8)
	end := ipv6.HeaderLen + payloadLen
	if end > len(p) {
		end = len(p)
	}
	if end < ipv6.HeaderLen {
		return 0, 0, 0, false
	}

	nextHeader := p[6]
	offset = ipv6.HeaderLen

	for {
		switch nextHeader {
		case ipProtoTCP, ipProtoUDP, ipProtoICMPv6:
			if offset >= end {
				return 0, 0, 0, false
			}
			return nextHeader, offset, end - offset, true
		case ipProtoHopByHop, ipProtoRouting, ipProtoDestOpts, ipProtoMobility, ipProtoHIP, ipProtoShim6:
			if offset+2 > end {
				return 0, 0, 0, false
			}
			extLen := (int(p[offset+1]) + 1) * 8
			nextHeader = p[offset]
			offset += extLen
			if offset > end {
				return 0, 0, 0, false
			}
		case ipProtoFragment:
			if offset+8 > end {
				return 0, 0, 0, false
			}
			nextHeader = p[offset]
			fragmentOffset := (uint16(p[offset+2])<<8 | uint16(p[offset+3])) >> 3
			if fragmentOffset != 0 {
				return 0, 0, 0, false
			}
			offset += 8
		case ipProtoAH:
			if offset+2 > end {
				return 0, 0, 0, false
			}
			extLen := (int(p[offset+1]) + 2) * 4
			nextHeader = p[offset]
			offset += extLen
			if offset > end {
				return 0, 0, 0, false
			}
		case ipProtoESP, ipProtoNoNext:
			return 0, 0, 0, false
		default:
			return 0, 0, 0, false
		}
	}
}
