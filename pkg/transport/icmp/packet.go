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

package icmp

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
)

type Packet struct {
	IPSrc       net.IP
	IPDst       net.IP
	IcmpType    ipv4.ICMPType
	IcmpCode    uint8
	IcmpEchoID  uint16
	IcmpSeq     uint16
	IcmpPayload []byte
	PacketSeq   uint32
	PacketAck   uint32
	Data        []byte
	buffer      []byte
}

func NewPacket(buffer []byte, len int) (*Packet, error) {
	p := &Packet{}
	p.buffer = buffer
	if err := p.Unmarshal(buffer[:len]); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *Packet) Unmarshal(data []byte) error {
	if len(data) < 20+icmpHeaderSize {
		return fmt.Errorf("packet too short")
	}
	// read ip fields
	p.IPSrc = data[12:16]
	p.IPDst = data[16:20]
	payloadOffset := int(data[0]&0x0F) << 2
	ipPayload := data[payloadOffset:]
	// read icmp fields
	p.IcmpType = ipv4.ICMPType(ipPayload[0])
	p.IcmpCode = ipPayload[1]
	p.IcmpEchoID = binary.BigEndian.Uint16(ipPayload[4:6])
	p.IcmpSeq = binary.BigEndian.Uint16(ipPayload[6:8])
	p.IcmpPayload = ipPayload[icmpHeaderSize:]
	if len(p.IcmpPayload) < eHeaderSize {
		return nil
	}
	// extract sequence and sequence and acknowledgment from payload
	p.PacketSeq, p.PacketAck = getSeqAck(p.IcmpPayload[:eHeaderSize])
	// strip our header
	p.Data = p.IcmpPayload[eHeaderSize:]
	return nil
}

func (p *Packet) IcmpPacket() string {
	return fmt.Sprintf("TYPE=%d, CODE=%d, ID=%d, SEQ=%d", p.IcmpType, p.IcmpCode, p.IcmpEchoID, p.IcmpSeq)
}

func (p *Packet) PigPacket() string {
	return fmt.Sprintf("SEQ=%d, ACK=%d, LEN=%d", p.PacketSeq, p.PacketAck, len(p.Data))
}
