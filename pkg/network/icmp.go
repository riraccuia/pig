package network

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// SendICMPv4TimeExceeded sends a ICMP time exceeded message to a remote address
// using raw sockets, golang.org/x/net/icmp is used to send the message
// localAddr is the local address of the sender
// remoteAddr is the remote address of the receiver
// eaddr is the address of the endpoint for the original packet embedded in the time exceeded message
func SendICMPv4TimeExceeded(localAddr, remoteAddr, eaddr net.IP) error {
	// Create a raw ICMP socket
	conn, err := net.ListenIP("ip4:icmp", nil)
	if err != nil {
		return fmt.Errorf("failed to create ICMP socket: %w", err)
	}
	defer conn.Close()

	// Create raw connection for sending
	rawConn, err := ipv4.NewRawConn(conn)
	if err != nil {
		return fmt.Errorf("failed to create raw connection: %w", err)
	}

	// Create fake IPv4 datagram for the DstUnreach data field
	// The datagram should have src IP as remoteAddr
	fakeDatagram := createFakeIPv4Datagram(remoteAddr, eaddr)

	// Create ICMP destination unreachable message
	msg := &icmp.Message{
		Type: ipv4.ICMPTypeTimeExceeded,
		Code: 0, // Time exceeded
		Body: &icmp.TimeExceeded{
			Data: fakeDatagram, // Fake IPv4 datagram
		},
	}

	// Marshal the message
	msgBytes, err := msg.Marshal(nil)
	if err != nil {
		rawConn.Close()
		return fmt.Errorf("failed to marshal ICMP message: %w", err)
	}

	// Create IP header
	header := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      20, // Standard IP header length
		TotalLen: 20 + len(msgBytes),
		Flags:    ipv4.DontFragment,
		TTL:      64,
		Protocol: 1, // ICMP protocol
		Src:      localAddr.To4(),
		Dst:      remoteAddr.To4(),
	}

	// Send the packet
	if err := rawConn.WriteTo(header, msgBytes, nil); err != nil {
		rawConn.Close()
		return fmt.Errorf("failed to send ICMP destination unreachable: %w", err)
	}

	return nil
}

// createFakeIPv4Datagram creates a fake IPv4 datagram with the specified source and destination IPs
// carrying an ICMP echo request packet
func createFakeIPv4Datagram(srcIP, dstIP net.IP) []byte {
	// IPv4 header (20 bytes) + ICMP echo request (8 bytes)
	datagram := make([]byte, 20+8) // 20 bytes header + 8 bytes ICMP echo request
	// Version and header length (4 bits each)
	datagram[0] = 0x45 // IPv4, header length 20 bytes
	// Type of Service
	datagram[1] = 0x00
	// Total Length (16 bits) - 28 bytes total
	binary.BigEndian.PutUint16(datagram[2:4], 28)
	// Identification (16 bits)
	binary.BigEndian.PutUint16(datagram[4:6], 0x1234)
	// Flags and Fragment Offset (16 bits)
	binary.BigEndian.PutUint16(datagram[6:8], 0x0000)
	// Time to Live
	datagram[8] = 64
	// Protocol (ICMP = 1)
	datagram[9] = 1
	// Header Checksum (16 bits) - will be calculated
	binary.BigEndian.PutUint16(datagram[10:12], 0x0000)
	// Source IP Address (32 bits)
	copy(datagram[12:16], srcIP.To4())
	// Destination IP Address (32 bits)
	copy(datagram[16:20], dstIP.To4())
	// Create ICMP echo request header (8 bytes)
	// Type: Echo Request (8)
	datagram[20] = 8
	// Code: 0
	datagram[21] = 0
	// Checksum: will be calculated
	binary.BigEndian.PutUint16(datagram[22:24], 0x0000)
	// Identifier: 0x1234
	binary.BigEndian.PutUint16(datagram[24:26], 0x1234)
	// Sequence Number: 0x0001
	binary.BigEndian.PutUint16(datagram[26:28], 0x0001)
	// Calculate and set ICMP checksum
	IPv4Packet(datagram).UpdateChecksum()
	return datagram
}
