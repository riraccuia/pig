package network

import (
	"encoding/binary"
	"encoding/hex"
	"net/netip"
	"testing"
)

func TestUDPChecksum(t *testing.T) {
	hexPktBytes := `4500003c3c8100004011920dac1ffe0101010101e2ec003500280000f8eb010000010000000000000377777706676f6f676c6503636f6d0000010001`
	expectedChecksum := uint16(0xe8c5)
	pktBytes, err := hex.DecodeString(hexPktBytes)
	if err != nil {
		t.Fatalf("failed to decode hex string: %v", err)
	}
	pkt := IPv4Packet(pktBytes)
	pkt.UpdateChecksum()
	got := binary.BigEndian.Uint16(pkt[pkt.PayloadOffset()+6 : pkt.PayloadOffset()+8])
	if got != expectedChecksum {
		t.Fatalf("udp checksum = %x, want %x", got, expectedChecksum)
	}
}

func TestIPv4UDPUpdateAndValidate(t *testing.T) {
	pkt := ipv4UDP([]byte("hello"))
	pkt.UpdateChecksum()
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	if !TransportChecksumValid(ProtocolUDP, src, dst, pkt[pkt.PayloadOffset():]) {
		t.Fatal("valid UDP checksum rejected")
	}
	pkt[len(pkt)-1] ^= 0xff
	if TransportChecksumValid(ProtocolUDP, src, dst, pkt[pkt.PayloadOffset():]) {
		t.Fatal("corrupted UDP checksum accepted")
	}
}

func TestIPv4TCPUpdateAndValidate(t *testing.T) {
	pkt := ipv4TCP([]byte("hi"))
	pkt.UpdateChecksum()
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	if !TransportChecksumValid(ProtocolTCP, src, dst, pkt[pkt.PayloadOffset():]) {
		t.Fatal("valid TCP checksum rejected")
	}
	pkt[len(pkt)-1] ^= 0xff
	if TransportChecksumValid(ProtocolTCP, src, dst, pkt[pkt.PayloadOffset():]) {
		t.Fatal("corrupted TCP checksum accepted")
	}
}

func TestIPv6UDPUpdateAndValidate(t *testing.T) {
	pkt := ipv6UDP([]byte("hello"))
	pkt.UpdateChecksum()
	src := netip.AddrFrom16([16]byte(pkt[8:24]))
	dst := netip.AddrFrom16([16]byte(pkt[24:40]))
	off := pkt.PayloadOffset()
	if !TransportChecksumValid(ProtocolUDP, src, dst, pkt[off:]) {
		t.Fatal("valid IPv6 UDP checksum rejected")
	}
	pkt[len(pkt)-1] ^= 0xff
	if TransportChecksumValid(ProtocolUDP, src, dst, pkt[off:]) {
		t.Fatal("corrupted IPv6 UDP checksum accepted")
	}
}

func TestIPv4HeaderChecksum(t *testing.T) {
	pkt := ipv4UDP(nil)
	pkt[10], pkt[11] = 0, 0
	pkt.UpdateChecksum()
	if pkt[10] == 0 && pkt[11] == 0 {
		t.Fatal("IP header checksum left at zero")
	}
	// A correct header checksum folds to 0xffff with the field included.
	if fold(addWords(0, pkt[:pkt.PayloadOffset()])) != 0xffff {
		t.Fatal("IP header checksum does not verify")
	}
}

func TestOddLengthPayload(t *testing.T) {
	payload := [3]byte{1, 2, 3} // 3-byte payload
	pkt := ipv4UDP(payload[:])
	pkt.UpdateChecksum()
	src := netip.AddrFrom4([4]byte(pkt[12:16]))
	dst := netip.AddrFrom4([4]byte(pkt[16:20]))
	if !TransportChecksumValid(ProtocolUDP, src, dst, pkt[pkt.PayloadOffset():]) {
		t.Fatal("odd-length UDP checksum rejected")
	}
}

func ipv4UDP(payload []byte) IPv4Packet {
	const ipLen = 20
	udpLen := 8 + len(payload)
	b := make([]byte, ipLen+udpLen)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = 64
	b[9] = ProtocolUDP
	copy(b[12:16], []byte{10, 0, 0, 1})
	copy(b[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(b[ipLen:ipLen+2], 12345)
	binary.BigEndian.PutUint16(b[ipLen+2:ipLen+4], 53)
	binary.BigEndian.PutUint16(b[ipLen+4:ipLen+6], uint16(udpLen))
	copy(b[ipLen+8:], payload)
	return IPv4Packet(b)
}

func ipv4TCP(payload []byte) IPv4Packet {
	const ipLen, tcpHdr = 20, 20
	b := make([]byte, ipLen+tcpHdr+len(payload))
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[8] = 64
	b[9] = ProtocolTCP
	copy(b[12:16], []byte{10, 0, 0, 1})
	copy(b[16:20], []byte{10, 0, 0, 2})
	binary.BigEndian.PutUint16(b[ipLen:ipLen+2], 12345)
	binary.BigEndian.PutUint16(b[ipLen+2:ipLen+4], 80)
	b[ipLen+12] = tcpHdr << 2 // data offset
	copy(b[ipLen+tcpHdr:], payload)
	return IPv4Packet(b)
}

func ipv6UDP(payload []byte) IPv6Packet {
	const ipLen = 40
	udpLen := 8 + len(payload)
	b := make([]byte, ipLen+udpLen)
	b[0] = 0x60
	binary.BigEndian.PutUint16(b[4:6], uint16(udpLen))
	b[6] = ProtocolUDP
	b[7] = 64
	copy(b[8:24], netip.MustParseAddr("fd00::1").AsSlice())
	copy(b[24:40], netip.MustParseAddr("fd00::2").AsSlice())
	binary.BigEndian.PutUint16(b[ipLen:ipLen+2], 12345)
	binary.BigEndian.PutUint16(b[ipLen+2:ipLen+4], 53)
	binary.BigEndian.PutUint16(b[ipLen+4:ipLen+6], uint16(udpLen))
	copy(b[ipLen+8:], payload)
	return IPv6Packet(b)
}
