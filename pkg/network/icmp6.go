package network

import (
	"encoding/binary"

	"golang.org/x/net/ipv6"
)

// NewICMPv6EchoRequest builds an ICMPv6 Echo Request packet with the given id and sequence number
func NewICMPv6EchoRequest(id, seq uint16, payloadLen int) (p []byte) {
	p = make([]byte, payloadLen)
	p[0] = uint8(ipv6.ICMPTypeEchoRequest)
	binary.BigEndian.PutUint16(p[4:6], id)
	binary.BigEndian.PutUint16(p[6:8], seq)
	return
}
