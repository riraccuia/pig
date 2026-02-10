package route

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestDarwinManager(t *testing.T) {
	manager, err := NewManager(context.Background())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	err = manager.AddRoute(&Route{
		Destination: &net.IPNet{
			IP:   net.IPv4(10, 0, 0, 1),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		//Gateway:   net.IPv4(192, 168, 2, 1),
		Interface: "utun8",
	})
	if err != nil {
		t.Fatalf("Failed to add route: %v", err)
	}
	time.Sleep(9 * time.Second)
	err = manager.RemoveRoute(&Route{
		Destination: &net.IPNet{
			IP:   net.IPv4(10, 0, 0, 1),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		//Gateway:   net.IPv4(192, 168, 2, 1),
		Interface: "utun8",
	})
	if err != nil {
		t.Fatalf("Failed to remove route: %v", err)
	}
	err = manager.Cleanup()
	if err != nil {
		t.Fatalf("Failed to cleanup: %v", err)
	}
	err = manager.Close()
	if err != nil {
		t.Fatalf("Failed to close manager: %v", err)
	}
}

func TestDarwinManagerAddRoute(t *testing.T) {
	manager, err := NewManager(context.Background())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	_, ipNet, err := net.ParseCIDR("128.0.0.0/1")
	if err != nil {
		t.Fatalf("Failed to parse CIDR: %v", err)
	}
	time.Sleep(1 * time.Second)
	err = manager.AddRoute(&Route{
		Destination: ipNet,
		Interface:   "utun8",
	})
	if err != nil {
		t.Fatalf("Failed to add route: %v", err)
	}
	_, ipNet, err = net.ParseCIDR("0.0.0.0/1")
	if err != nil {
		t.Fatalf("Failed to parse CIDR: %v", err)
	}
	err = manager.AddRoute(&Route{
		Destination: ipNet,
		Interface:   "utun8",
	})
	if err != nil {
		t.Fatalf("Failed to add route: %v", err)
	}
	err = manager.Close()
	if err != nil {
		t.Fatalf("Failed to close manager: %v", err)
	}
}

func TestDarwinManagerDeleteRoute(t *testing.T) {
	manager, err := NewManager(context.Background())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	err = manager.AddRoute(&Route{
		Destination: &net.IPNet{
			IP:   net.IPv4(10, 0, 0, 0),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		Gateway: net.IPv4(192, 168, 2, 1),
		//Interface: "en0",
	})
	if err != nil {
		t.Fatalf("Failed to add route: %v", err)
	}
	time.Sleep(1 * time.Second)
	err = manager.RemoveRoute(&Route{
		Destination: &net.IPNet{
			IP:   net.IPv4(10, 0, 0, 0),
			Mask: net.IPv4Mask(255, 255, 255, 0),
		},
		Gateway: net.IPv4(192, 168, 2, 1),
		//Interface: "en0",
	})
	if err != nil {
		t.Fatalf("Failed to remove route: %v", err)
	}
	err = manager.Close()
	if err != nil {
		t.Fatalf("Failed to close manager: %v", err)
	}
}

func TestDarwinManagerGetRoutes(t *testing.T) {
	manager, err := NewManager(context.Background())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	routes, err := manager.GetRoutes()
	if err != nil {
		t.Fatalf("Failed to get routes: %v", err)
	}
	for _, _route := range routes {
		if !_route.Destination.IP.To4().Equal(net.ParseIP("0.0.0.0")) {
			//continue
		}
		t.Logf("Route (valid gateway: %v): %v", isValidGateway(_route.Gateway, unix.RTM_GET), _route)
	}
	err = manager.Close()
	if err != nil {
		t.Fatalf("Failed to close manager: %v", err)
	}
}

func TestDarwinManagerDefaultGateways(t *testing.T) {
	manager, err := NewManager(context.Background())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer manager.Close()

	// Allow time for reconnaissance to complete
	time.Sleep(100 * time.Millisecond)

	// Get default gateways
	gw4 := manager.GetDefaultGateway4()
	gw6 := manager.GetDefaultGateway6()

	t.Logf("IPv4 default gateway: %v", gw4)
	t.Logf("IPv6 default gateway: %v", gw6)
}

func TestDarwinManagerWaitDefaultGateway(t *testing.T) {
	manager, err := NewManager(context.Background())
	if err != nil {
		t.Fatalf("Failed to create manager: %v", err)
	}
	defer manager.Close()
	manager.WaitDefaultGateway(true, true)
	t.Logf("Default gateway: %v", manager.GetDefaultGateway6())
}
