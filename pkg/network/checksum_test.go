package network

import (
	"encoding/binary"
	"encoding/hex"
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
	calculatedCsum := binary.BigEndian.Uint16(pkt[pkt.PayloadOffset()+6 : pkt.PayloadOffset()+8])
	t.Logf("udpCsum: %x\n", calculatedCsum)
	if expectedChecksum != calculatedCsum {
		t.Fatalf("expected checksum %x, got %x", expectedChecksum, calculatedCsum)
	}
}
