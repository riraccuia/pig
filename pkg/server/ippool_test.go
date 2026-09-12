package server

import (
	"net"
	"testing"
)

func TestIPv4IPPool(t *testing.T) {
	prefix := "192.168.1.0/24"
	expectedIP := net.ParseIP("192.168.1.2")

	_, ipNet4, err := net.ParseCIDR(prefix)
	if err != nil {
		t.Fatalf("Failed to parse CIDR: %v", err)
	}
	ipPool := newIPPool(ipNet4)
	ip, err := ipPool.Allocate()
	if err != nil {
		t.Fatalf("Failed to allocate IP: %v", err)
	}
	if !ip.Equal(expectedIP) {
		t.Fatalf("Unexpected allocated IP: %s", ip.String())
	}
	t.Logf("Allocated IPv4: %s", ip.String())
}

func TestIPv6IPPool(t *testing.T) {
	prefix := "2a51:ae0:64f:4e93::/64"
	expectedIP := net.ParseIP("2a51:ae0:64f:4e93::2")

	_, ipNet6, err := net.ParseCIDR(prefix)
	if err != nil {
		t.Fatalf("Failed to parse CIDR: %v", err)
	}
	ipPool := newIPPool(ipNet6)
	ip, err := ipPool.Allocate()
	if err != nil {
		t.Fatalf("Failed to allocate IP: %v", err)
	}
	if !ip.Equal(expectedIP) {
		t.Fatalf("Unexpected allocated IP: %s", ip.String())
	}
	t.Logf("Allocated IPv6: %s", ip.String())
}
