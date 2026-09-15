//go:build manual

package network

import (
	"net"
	"testing"
)

func TestDiscoverPMTU(t *testing.T) {
	pmtu, err := PathMTUDiscovery6(net.ParseIP("2606:4700::6812:1a78"))
	if err != nil {
		t.Fatalf("failed to discover PMTU: %v", err)
	}
	t.Logf("PMTU: %d", pmtu)
}
