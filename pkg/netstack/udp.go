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

package netstack

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const udpHeaderLen = 8

var errBadUDPLength = errors.New("netstack: invalid UDP length")

// udpDatagram is a UDP header plus payload (RFC 768).
type udpDatagram struct {
	srcPort uint16
	dstPort uint16
	payload []byte
}

// parseUDP decodes b without copying. It also returns the bytes covered by
// the UDP length field, which is what the checksum is computed over.
func parseUDP(b []byte) (udpDatagram, []byte, error) {
	if len(b) < udpHeaderLen {
		return udpDatagram{}, nil, errBadUDPLength
	}
	length := int(binary.BigEndian.Uint16(b[4:6]))
	if length < udpHeaderLen || length > len(b) {
		return udpDatagram{}, nil, errBadUDPLength
	}
	wire := b[:length]
	return udpDatagram{
		srcPort: binary.BigEndian.Uint16(b[0:2]),
		dstPort: binary.BigEndian.Uint16(b[2:4]),
		payload: wire[udpHeaderLen:],
	}, wire, nil
}

func (d *udpDatagram) proto() uint8 { return protoUDP }

func (d *udpDatagram) wireLen() int { return udpHeaderLen + len(d.payload) }

func (d *udpDatagram) marshal(b []byte) {
	binary.BigEndian.PutUint16(b[0:2], d.srcPort)
	binary.BigEndian.PutUint16(b[2:4], d.dstPort)
	binary.BigEndian.PutUint16(b[4:6], uint16(d.wireLen()))
	clear(b[6:8])
	copy(b[udpHeaderLen:], d.payload)
}

// inputUDP delivers an inbound datagram to the socket bound to its
// destination. Datagrams for unbound ports are dropped.
func (s *Stack) inputUDP(dg datagram) {
	d, wire, err := parseUDP(dg.payload)
	if err != nil {
		s.logger.Debugf("netstack: dropping UDP datagram from %s: %v", dg.src, err)
		return
	}
	if !udpChecksumValid(dg, wire) {
		s.logger.Debugf("netstack: dropping UDP datagram with bad checksum from %s", dg.src)
		return
	}
	local := netip.AddrPortFrom(dg.dst, d.dstPort)
	from := netip.AddrPortFrom(dg.src, d.srcPort)
	u := s.lookupUDP(local)
	if u == nil {
		s.logger.Tracef("netstack: dropping UDP datagram for unbound %s", local)
		return
	}
	if !u.deliver(from, d.payload) {
		s.logger.Tracef("netstack: UDP socket %s dropped datagram from %s", local, from)
	}
}

// udpChecksumValid accepts a zero checksum ("none computed") only over IPv4
// (RFC 768); IPv6 makes the UDP checksum mandatory (RFC 8200 §8.1).
func udpChecksumValid(dg datagram, wire []byte) bool {
	if binary.BigEndian.Uint16(wire[6:8]) == 0 {
		return dg.src.Is4()
	}
	return checksumValid(protoUDP, dg.src, dg.dst, wire)
}
