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
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"time"

	"golang.org/x/net/ipv4"
)

// DialTCP uses a net.Dialer to dial a TCP connection and sets the SO_REUSEADDR and TCP_NODELAY options.
func DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	dialer := NewDialer(5 * time.Second)
	return dialTCP(context.Background(), dialer, network, laddr, raddr)
}

func DialTCPContext(ctx context.Context, network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	dialer := NewDialer(5 * time.Second)
	return dialTCP(ctx, dialer, network, laddr, raddr)
}

// SendSYN sends a SYN packet to the remote side of the connection.
// The connection's local address must not be bound to 0.0.0.0 or ::.
func SendSYNPacket(ipConn *net.IPConn, srcPort, dstPort uint16) error {
	// Build a fake ip header so that we can compute the checksum
	laddr := ipConn.LocalAddr().(*net.IPAddr)
	raddr := ipConn.RemoteAddr().(*net.IPAddr)

	var (
		packetBytes []byte
		headerLen   int
		ipPacket    IPPacket
	)
	switch {
	case laddr.IP.To4() != nil:
		headerLen = 20
		packetBytes = make([]byte, headerLen+20)
		ipHeader := ipv4.Header{
			Version:  4,
			Len:      20,
			TotalLen: 40,
			TTL:      64,
			Protocol: ipProtoTCP,
			Src:      laddr.IP.To4(),
			Dst:      raddr.IP.To4(),
		}
		ipHeaderBytes, err := ipHeader.Marshal()
		if err != nil {
			return err
		}
		copy(packetBytes, ipHeaderBytes)
		// Ensure total length is correct, this is because, on darwin, this field is written using native endianness.
		binary.BigEndian.PutUint16(packetBytes[2:4], 40)
		ipPacket = IPv4Packet(packetBytes)
	case laddr.IP.To16() != nil:
		headerLen = 40
		packetBytes = make([]byte, headerLen+20)
		packetBytes[0] = byte(6 << 4) // version 6
		// Payload length
		binary.BigEndian.PutUint16(packetBytes[4:6], 20)
		// Next header
		packetBytes[6] = ipProtoTCP
		// Hop limit
		packetBytes[7] = 64
		// Source address
		copy(packetBytes[8:24], laddr.IP.To16())
		copy(packetBytes[24:40], raddr.IP.To16())
		ipPacket = IPv6Packet(packetBytes)
	default:
		return errors.New("invalid ip address family")
	}

	// Create a TCP header
	tcpHeader := packetBytes[headerLen:]

	sequenceNumber := rand.Uint32()
	acknowledgmentNumber := uint32(0)

	// Source port
	binary.BigEndian.PutUint16(tcpHeader[0:2], srcPort)
	// Destination port
	binary.BigEndian.PutUint16(tcpHeader[2:4], dstPort)
	// Sequence number
	binary.BigEndian.PutUint32(tcpHeader[4:8], sequenceNumber)
	// Acknowledgment number
	binary.BigEndian.PutUint32(tcpHeader[8:12], acknowledgmentNumber)
	// Flags
	tcpHeader[12] = 5 << 4 // 20 bytes data offset
	tcpHeader[13] = 1 << 1 // SYN
	// Window size
	tcpHeader[14] = 0xFF
	tcpHeader[15] = 0xFF

	// Options

	// MSS option
	/*tcpHeader[20] = 2
	tcpHeader[21] = 4
	binary.BigEndian.PutUint16(tcpHeader[22:24], mss)*/

	ipPacket.UpdateChecksum()

	// Send the SYN packet
	_, err := ipConn.Write(packetBytes[headerLen:])
	return err
}
