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

	"github.com/riraccuia/pig/pkg/network"
)

const (
	ipv4HeaderLen = 20
	ipv6HeaderLen = 40
	protoTCP      = 6
	protoUDP      = 17
	defaultTTL    = 64
	ipv4FlagDF    = 0x40
	ipv4FragMask  = 0x3fff // MF flag and fragment offset
)

var (
	errShortDatagram       = errors.New("netstack: datagram too short")
	errBadVersion          = errors.New("netstack: unsupported IP version")
	errBadHeader           = errors.New("netstack: malformed IP header")
	errFragmented          = errors.New("netstack: fragmented datagrams are not supported")
	errUnsupportedProtocol = errors.New("netstack: unsupported transport protocol")
)

// transport is a TCP segment or UDP datagram ready to be wrapped in IP.
type transport interface {
	proto() uint8
	wireLen() int
	// marshal writes the transport header and payload with a zero checksum.
	marshal(b []byte)
}

// datagram is a parsed inbound IP packet; payload aliases the original buffer.
type datagram struct {
	proto   uint8
	src     netip.Addr
	dst     netip.Addr
	payload []byte
}

func supportedProtocol(proto uint8) bool {
	return proto == protoTCP || proto == protoUDP
}

// ipHeaderLen is the length of the IP header this stack emits for addr's family.
func ipHeaderLen(addr netip.Addr) int {
	if addr.Is4() {
		return ipv4HeaderLen
	}
	return ipv6HeaderLen
}

func parseDatagram(b []byte) (datagram, error) {
	if len(b) < 1 {
		return datagram{}, errShortDatagram
	}
	switch b[0] >> 4 {
	case 4:
		return parseIPv4(b)
	case 6:
		return parseIPv6(b)
	}
	return datagram{}, errBadVersion
}

func parseIPv4(b []byte) (datagram, error) {
	if len(b) < ipv4HeaderLen {
		return datagram{}, errShortDatagram
	}
	ihl := int(b[0]&0x0f) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < ipv4HeaderLen || total < ihl || total > len(b) {
		return datagram{}, errBadHeader
	}
	if binary.BigEndian.Uint16(b[6:8])&ipv4FragMask != 0 {
		return datagram{}, errFragmented
	}
	if !supportedProtocol(b[9]) {
		return datagram{}, errUnsupportedProtocol
	}
	return datagram{
		proto:   b[9],
		src:     netip.AddrFrom4([4]byte(b[12:16])),
		dst:     netip.AddrFrom4([4]byte(b[16:20])),
		payload: b[ihl:total],
	}, nil
}

// parseIPv6 accepts only a transport header directly after the fixed header;
// extension headers are not supported.
func parseIPv6(b []byte) (datagram, error) {
	if len(b) < ipv6HeaderLen {
		return datagram{}, errShortDatagram
	}
	end := ipv6HeaderLen + int(binary.BigEndian.Uint16(b[4:6]))
	if end > len(b) {
		return datagram{}, errBadHeader
	}
	if !supportedProtocol(b[6]) {
		return datagram{}, errUnsupportedProtocol
	}
	return datagram{
		proto:   b[6],
		src:     netip.AddrFrom16([16]byte(b[8:24])),
		dst:     netip.AddrFrom16([16]byte(b[24:40])),
		payload: b[ipv6HeaderLen:end],
	}, nil
}

// buildDatagram wraps t in an IPv4 or IPv6 header chosen by the address
// family of src and fills in all checksums.
func buildDatagram(src, dst netip.Addr, t transport) []byte {
	if src.Is4() {
		return buildIPv4(src, dst, t)
	}
	return buildIPv6(src, dst, t)
}

func buildIPv4(src, dst netip.Addr, t transport) []byte {
	b := make([]byte, ipv4HeaderLen+t.wireLen())
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[6] = ipv4FlagDF
	b[8] = defaultTTL
	b[9] = t.proto()
	src4, dst4 := src.As4(), dst.As4()
	copy(b[12:16], src4[:])
	copy(b[16:20], dst4[:])
	t.marshal(b[ipv4HeaderLen:])
	network.IPv4Packet(b).UpdateChecksum()
	return b
}

func buildIPv6(src, dst netip.Addr, t transport) []byte {
	b := make([]byte, ipv6HeaderLen+t.wireLen())
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(t.wireLen()))
	b[6] = t.proto()
	b[7] = defaultTTL
	src16, dst16 := src.As16(), dst.As16()
	copy(b[8:24], src16[:])
	copy(b[24:40], dst16[:])
	t.marshal(b[ipv6HeaderLen:])
	network.IPv6Packet(b).UpdateChecksum()
	return b
}
