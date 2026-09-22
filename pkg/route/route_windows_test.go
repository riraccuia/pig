//go:build windows && manual

package route

import (
	"net"
	"testing"

	"github.com/riraccuia/pig/pkg/bindings/win"
)

func TestGetIpNetEntry2(t *testing.T) {
	itf, _ := net.InterfaceByName("WiFi")
	// convert index to luic
	luid, err := win.ConvertInterfaceIndexToLuid(uint32(itf.Index))
	if err != nil {
		t.Fatalf("ConvertInterfaceIndexToLuid failed: %v", err)
	}
	la := getLinkAddr(luid, net.IPv4(192, 168, 1, 1))
	if la == nil {
		t.Fatalf("getLinkAddr failed: %v", err)
	}
	t.Logf("link address: %v", la)
}
