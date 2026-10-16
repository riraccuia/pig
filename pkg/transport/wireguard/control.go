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

package wireguard

import (
	"encoding/binary"
	"net"
	"os"

	"github.com/riraccuia/pig/pkg/network"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

/*
Control messages carry non-IP pig payloads (e.g. auth tokens) across
wireguard-go, which only forwards L3 packets.
Wrap builds a special IPv4+ICMP echo header around the payload.
The final message gets DSCP marked as signaling traffic (40).
Unwrap checks an incoming packet for the special headers and, if found,
returns the original payload stripped of all artificial headers.
*/

var (
	CONTROL_MESSAGE_DSCP_MARK = byte(40) // signaling traffic
	CONTROL_MESSAGE_PROTOCOL  = 1        // icmp
	CONTROL_MESSAGE_TTL       = 1
	CONTROL_MESSAGE_SRC       = net.IPv4zero
	CONTROL_MESSAGE_DST       = net.IPv4zero
	CONTROL_MESSAGE_ID        = os.Getpid() & 0xffff
)

func newControlMessageFromPayload(b []byte) ([]byte, error) {
	icmpMsg := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   os.Getpid() & 0xffff,
			Seq:  1,
			Data: b,
		},
	}

	icmpData, err := icmpMsg.Marshal(nil)
	if err != nil {
		return nil, err
	}

	h := &ipv4.Header{
		Version:  4,
		Len:      ipv4.HeaderLen,
		TotalLen: len(icmpData) + ipv4.HeaderLen,
		Protocol: CONTROL_MESSAGE_PROTOCOL,
		Src:      CONTROL_MESSAGE_SRC,
		Dst:      CONTROL_MESSAGE_DST,
		TTL:      CONTROL_MESSAGE_TTL,
	}

	ipV4Header, err := h.Marshal()
	if err != nil {
		return nil, err
	}

	out := append(ipV4Header, icmpData...)
	// we write our own length because on some platforms, like darwin, ipv4.Header.Marshal()
	// sets the length as little endian, which other platforms (e.g. linux) will not understand.
	binary.BigEndian.PutUint16(out[2:4], uint16(h.TotalLen))
	binary.BigEndian.PutUint16(out[6:8], 0)
	outPkt := network.IPv4Packet(out)
	outPkt.Mark(CONTROL_MESSAGE_DSCP_MARK)
	outPkt.UpdateChecksum()
	return outPkt, nil
}

func (c *Conn) WrapControlMessage(b []byte) ([]byte, bool) {
	if len(b) < ipv4.HeaderLen {
		return b, false
	}
	var (
		pkt              network.IPPacket
		invalidIPVersion bool
	)
	switch network.IPv4Packet(b[:ipv4.HeaderLen]).Version() {
	case 6:
		pkt = network.IPv6Packet(b)
	case 4:
		pkt = network.IPv4Packet(b)
	default:
		invalidIPVersion = true
	}
	if !invalidIPVersion && pkt.TotalLength() == len(b) {
		return b, false
	}
	ctrlMsg, err := newControlMessageFromPayload(b)
	if err != nil {
		return b, false
	}
	return ctrlMsg, true
}

func (c *Conn) UnwrapControlMessage(to, from []byte) (int, bool) {
	if len(from) < ipv4.HeaderLen {
		return 0, false
	}
	pkt := network.IPv4Packet(from[:ipv4.HeaderLen])
	ver := pkt.Version()
	if ver != 4 {
		return 0, false
	}
	if pkt.GetMark() != CONTROL_MESSAGE_DSCP_MARK {
		return 0, false
	}
	if pkt.Protocol() != uint8(CONTROL_MESSAGE_PROTOCOL) {
		return 0, false
	}
	if !pkt.SourceIP().Equal(CONTROL_MESSAGE_SRC) {
		return 0, false
	}
	if !pkt.DestinationIP().Equal(CONTROL_MESSAGE_DST) {
		return 0, false
	}
	out := from[ipv4.HeaderLen+8 : pkt.TotalLength()]
	n := copy(to, out)
	if n < len(out) {
		c.readPending.Write(out[n:])
	}
	return n, true
}
