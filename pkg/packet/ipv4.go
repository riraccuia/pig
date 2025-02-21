package packet

import (
	"encoding/binary"
	"net"
)

type IPv4Packet []byte

func (p IPv4Packet) Version() int {
	return int(p[0] >> 4)
}

func (p IPv4Packet) SetSourceIP(ip net.IP) {
	copy(p[12:16], ip.To4())
	p.UpdateChecksum()
}

func (p IPv4Packet) SetDestinationIP(ip net.IP) {
	copy(p[16:20], ip.To4())
	p.UpdateChecksum()
}

func (p IPv4Packet) TotalLength() int {
	return int(uint16(p[3]) | uint16(p[2])<<8)
}

func (p IPv4Packet) TotalLengthLE() uint16 {
	return binary.NativeEndian.Uint16(p[2:4])
	//return uint16(p[2]) | uint16(p[3])<<8
}

func (p IPv4Packet) DestinationIP() net.IP {
	return net.IP(p[16:20])
}

func (p IPv4Packet) SourceIP() net.IP {
	return net.IP(p[12:16])
}

func (p IPv4Packet) Protocol() uint8 {
	return p[9]
}

func (p IPv4Packet) SourcePort() uint16 {
	if p.Protocol() != 6 && p.Protocol() != 17 {
		return 0
	}
	return uint16(p[21]) | uint16(p[20])<<8
}

func (p IPv4Packet) DestinationPort() uint16 {
	if p.Protocol() != 6 && p.Protocol() != 17 {
		return 0
	}
	return uint16(p[23]) | uint16(p[22])<<8
}

func (p IPv4Packet) PayloadOffset() int {
	return int(p[0]&0x0F) << 2 // IHL * 4 gives header length in bytes
}
