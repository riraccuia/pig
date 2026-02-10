package ice

import (
	"net"
	"sync"
	"testing"

	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/stun"
	"github.com/riraccuia/pig/pkg/transport"
)

// getIPFromAddr extracts the IP address from a net.Addr
func getIPFromAddr(addr net.Addr) net.IP {
	switch v := addr.(type) {
	case *net.UDPAddr:
		return v.IP
	case *net.TCPAddr:
		return v.IP
	case *net.IPAddr:
		return v.IP
	default:
		return nil
	}
}

// testConnectPaths is a utility function that tests ICE binding agent communication
// between two connect paths with the specified protocol and addresses
func testConnectPaths(t *testing.T, protocol transport.ICEProtocolDefinition, laddr, raddr net.Addr) {
	logger := log.NewBlockingLogger()
	logger.SetLevel("debug")

	cp1 := &ConnectPath{
		LocalAddr:  laddr,
		RemoteAddr: raddr,
		Protocol:   protocol,
		BindAgent:  stun.NewIceBindingAgent(logger, nil),
	}
	cp2 := &ConnectPath{
		LocalAddr:  raddr,
		RemoteAddr: laddr,
		Protocol:   protocol,
		BindAgent:  stun.NewIceBindingAgent(logger, nil),
	}

	cp1.BindAgent.Ice = &stun.IceAttributes{
		Priority:       100,
		IceControlling: 1,
	}
	cp2.BindAgent.Ice = &stun.IceAttributes{
		Priority:      100,
		IceControlled: 1,
	}

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		cp2.Connect()
		cp2.BindAgent.Receive()
	}()
	go func() {
		defer wg.Done()
		cp1.Connect()
	}()
	wg.Wait()

	// Test cp1 -> cp2 binding
	r, err := cp1.BindAgent.SendBindingRequest(true)
	if err != nil {
		t.Errorf("Failed to send binding request: %v", err)
		return
	}
	expectedIP := getIPFromAddr(cp1.LocalAddr)
	if expectedIP == nil {
		t.Errorf("Failed to extract IP from local address")
		return
	}
	if !r.IP.Equal(expectedIP) {
		t.Errorf("Expected %s, got %s", expectedIP, r.IP)
		return
	}

	// Test cp2 -> cp1 binding
	cp1.BindAgent.Receive()
	cp2.BindAgent.StopReceive()
	r, err = cp2.BindAgent.SendBindingRequest(true)
	if err != nil {
		t.Errorf("Failed to send binding request: %v", err)
		return
	}
	expectedIP = getIPFromAddr(cp2.LocalAddr)
	if expectedIP == nil {
		t.Errorf("Failed to extract IP from local address")
		return
	}
	if !r.IP.Equal(expectedIP) {
		t.Errorf("Expected %s, got %s", expectedIP, r.IP)
		return
	}
}

func TestUDPConnectPaths(t *testing.T) {
	laddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 12345,
	}
	raddr := &net.UDPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 12346,
	}
	testConnectPaths(t, transport.ICEProtocolQUIC, laddr, raddr)
}

func TestTCPConnectPaths(t *testing.T) {
	laddr := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 12347,
	}
	raddr := &net.TCPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Port: 12348,
	}
	testConnectPaths(t, transport.ICEProtocolWS, laddr, raddr)
}
func TestGetLocalNetworks(t *testing.T) {
	ipNets, ips, err := GetLocalNetworks("")
	if err != nil {
		t.Errorf("Failed to get local networks: %v", err)
		return
	}
	for _, ipNet := range ipNets {
		t.Logf("Local network: %s", ipNet.String())
	}
	for _, ip := range ips {
		t.Logf("Local IP: %s", ip.String())
	}
}
