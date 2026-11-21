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
)

const (
	flagFIN uint8 = 0x01
	flagSYN uint8 = 0x02
	flagRST uint8 = 0x04
	flagPSH uint8 = 0x08
	flagACK uint8 = 0x10
	flagURG uint8 = 0x20

	tcpHeaderLen = 20
)

var (
	errShortSegment = errors.New("netstack: TCP segment too short")
	errBadOffset    = errors.New("netstack: invalid TCP data offset")
)

// segment is a decoded TCP header plus payload (RFC 9293 §3.1). Parsed
// segments carry their bytes in payload; outbound data segments reference
// the send buffer through text instead, so the data is copied only once,
// straight into the outgoing packet.
type segment struct {
	srcPort uint16
	dstPort uint16
	seq     uint32
	ack     uint32
	flags   uint8
	window  uint16
	opts    tcpOptions
	payload []byte
	text    ringSlice
}

// ringSlice is n bytes of a ring buffer starting off bytes past its head.
// The buffer must not change until the segment has been marshaled.
type ringSlice struct {
	buf *ringBuffer
	off int
	n   int
}

// parseSegment decodes b without copying; payload aliases b.
func parseSegment(b []byte) (segment, error) {
	if len(b) < tcpHeaderLen {
		return segment{}, errShortSegment
	}
	offset := int(b[12]>>4) * 4
	if offset < tcpHeaderLen || offset > len(b) {
		return segment{}, errBadOffset
	}
	return segment{
		srcPort: binary.BigEndian.Uint16(b[0:2]),
		dstPort: binary.BigEndian.Uint16(b[2:4]),
		seq:     binary.BigEndian.Uint32(b[4:8]),
		ack:     binary.BigEndian.Uint32(b[8:12]),
		flags:   b[13] & 0x3f,
		window:  binary.BigEndian.Uint16(b[14:16]),
		opts:    parseOptions(b[tcpHeaderLen:offset]),
		payload: b[offset:],
	}, nil
}

func (s *segment) has(flag uint8) bool { return s.flags&flag == flag }

func (s *segment) hasAny(flags uint8) bool { return s.flags&flags != 0 }

func (s *segment) payloadLen() int { return len(s.payload) + s.text.n }

// length is SEG.LEN: payload plus one for each of SYN and FIN.
func (s *segment) length() uint32 {
	n := uint32(s.payloadLen())
	if s.has(flagSYN) {
		n++
	}
	if s.has(flagFIN) {
		n++
	}
	return n
}

func (s *segment) proto() uint8 { return protoTCP }

func (s *segment) headerLen() int { return tcpHeaderLen + s.opts.encodedLen() }

func (s *segment) wireLen() int { return s.headerLen() + s.payloadLen() }

// marshal writes the segment into b with a zero checksum; the IP layer fills it.
func (s *segment) marshal(b []byte) {
	hl := s.headerLen()
	binary.BigEndian.PutUint16(b[0:2], s.srcPort)
	binary.BigEndian.PutUint16(b[2:4], s.dstPort)
	binary.BigEndian.PutUint32(b[4:8], s.seq)
	binary.BigEndian.PutUint32(b[8:12], s.ack)
	b[12] = byte(hl/4) << 4
	b[13] = s.flags
	binary.BigEndian.PutUint16(b[14:16], s.window)
	clear(b[16:20])
	s.opts.encode(b[tcpHeaderLen:hl])
	n := copy(b[hl:], s.payload)
	if s.text.n > 0 {
		s.text.buf.Peek(s.text.off, b[hl+n:hl+n+s.text.n])
	}
}
