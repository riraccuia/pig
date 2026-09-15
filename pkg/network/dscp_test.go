package network

import (
	"testing"
)

func TestDSCPMarkSetAndGet(t *testing.T) {
	tests := []struct {
		name     string
		mark     byte
		expected byte
	}{
		{"SRV_SNAT", DSCP_MARK_ADAPTER_SNAT, DSCP_MARK_ADAPTER_SNAT},
		{"CLI_SNAT", DSCP_MARK_MASQ_SNAT, DSCP_MARK_MASQ_SNAT},
		{"SRV_DNAT", DSCP_MARK_ADAPTER_DNAT, DSCP_MARK_ADAPTER_DNAT},
		{"CLI_DNAT", DSCP_MARK_MASQ_DNAT, DSCP_MARK_MASQ_DNAT},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a minimal IPv4 packet with header
			packet := make(IPv4Packet, 20)
			packet[0] = 0x45 // Version 4, IHL 5
			packet[1] = 0x00 // DSCP and ECN initially 0

			// Set the DSCP mark
			packet.Mark(tt.mark)

			// Verify the mark was set correctly
			got := packet.GetMark()
			if got != tt.expected {
				t.Errorf("GetMark() = %d, want %d", got, tt.expected)
			}

			// Verify ECN bits are preserved (should be 0)
			ecnBits := packet[1] & 0b00000011
			if ecnBits != 0 {
				t.Errorf("ECN bits not preserved, got %d, want 0", ecnBits)
			}
		})
	}
}

func TestDSCPMarkWithECN(t *testing.T) {
	// Test that DSCP marking preserves existing ECN bits
	packet := make(IPv4Packet, 20)
	packet[0] = 0x45 // Version 4, IHL 5

	// Set ECN bits to ECT(1) = 0b01
	packet[1] = 0b00000001

	// Mark with SRV_SNAT
	packet.Mark(DSCP_MARK_ADAPTER_SNAT)

	// Verify DSCP mark is correct
	got := packet.GetMark()
	if got != DSCP_MARK_ADAPTER_SNAT {
		t.Errorf("GetMark() = %d, want %d", got, DSCP_MARK_ADAPTER_SNAT)
	}

	// Verify ECN bits are preserved
	ecnBits := packet[1] & 0b00000011
	if ecnBits != 0b00000001 {
		t.Errorf("ECN bits not preserved, got %d, want 1", ecnBits)
	}
}

func TestDSCPClearMark(t *testing.T) {
	packet := make(IPv4Packet, 20)
	packet[0] = 0x45 // Version 4, IHL 5

	// Set ECN bits to CE = 0b11
	packet[1] = 0b00000011

	// Mark with CLI_DNAT
	packet.Mark(DSCP_MARK_MASQ_DNAT)

	// Verify mark is set
	if packet.GetMark() != DSCP_MARK_MASQ_DNAT {
		t.Errorf("Mark not set correctly")
	}

	// Clear the mark
	packet.ClearMark()

	// Verify mark is cleared
	if packet.GetMark() != 0 {
		t.Errorf("GetMark() after ClearMark() = %d, want 0", packet.GetMark())
	}

	// Verify ECN bits are still preserved
	ecnBits := packet[1] & 0b00000011
	if ecnBits != 0b00000011 {
		t.Errorf("ECN bits not preserved after ClearMark(), got %d, want 3", ecnBits)
	}
}
