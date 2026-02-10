package stun

import (
	"net"
	"testing"
)

func TestXorMappedAddressIPv6(t *testing.T) {
	txID := [12]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c}
	addr := &net.UDPAddr{
		IP:   net.ParseIP("2001:db8::1"),
		Port: 3478,
	}

	attr, err := CreateXorMappedAddress(addr, txID)
	if err != nil {
		t.Fatalf("CreateXorMappedAddress failed: %v", err)
	}

	ip, port, err := ExtractMappedAddress(attr, txID)
	if err != nil {
		t.Fatalf("ExtractMappedAddress failed: %v", err)
	}

	if !ip.Equal(addr.IP) {
		t.Fatalf("unexpected IP: got %v want %v", ip, addr.IP)
	}

	if port != addr.Port {
		t.Fatalf("unexpected port: got %d want %d", port, addr.Port)
	}
}
