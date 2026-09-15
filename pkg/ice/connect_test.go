package ice

import (
	"fmt"
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
		BindAgent:  stun.NewBindingAgent(&stun.BindingAgentConfig{Logger: logger.PrintLevel}),
	}
	cp2 := &ConnectPath{
		LocalAddr:  raddr,
		RemoteAddr: laddr,
		Protocol:   protocol,
		BindAgent:  stun.NewBindingAgent(&stun.BindingAgentConfig{Logger: logger.PrintLevel}),
	}

	cp1.BindAgent.SetConfig(stun.NewControllingICEBindingAgentConfig(logger.PrintLevel, nil, 100))
	cp2.BindAgent.SetConfig(stun.NewControlledICEBindingAgentConfig(logger.PrintLevel, nil, 100))

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		cp2.Connect()
	}()
	go func() {
		defer wg.Done()
		cp1.Connect()
	}()
	wg.Wait()

	// Test cp1 -> cp2 binding
	r, err := cp1.BindAgent.SendRequest(true)
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
	r, err = cp2.BindAgent.SendRequest(true)
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

func TestGetLocalEndpoints(t *testing.T) {
	endpoints, err := GetLocalEndpoints("", nil)
	if err != nil {
		t.Errorf("Failed to get local networks: %v", err)
		return
	}
	for _, endpoint := range endpoints {
		t.Logf("Local endpoint: Address %s, Network %s", endpoint.IP.String(), endpoint.Net.String())
	}
}

func TestNATConnectPathsProbabilityEquivalence(t *testing.T) {
	publicPath := &ConnectPath{
		LocalAddr: &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 12347,
		},
		RemoteAddr: &net.TCPAddr{
			IP:   net.IPv4(127, 0, 0, 1),
			Port: 12348,
		},
		Protocol: transport.ICEProtocolWS,
	}
	reversedPublicPath := &ConnectPath{
		LocalNet: &net.IPNet{
			IP:   net.IPv4(127, 0, 0, 2),
			Mask: net.CIDRMask(32, 32),
		},
		LocalAddr:  publicPath.RemoteAddr,
		RemoteAddr: publicPath.LocalAddr,
		Protocol:   publicPath.Protocol,
	}
	var matchedCount int
	for range 1000 {
		pc := NewPathConnector(nil, nil, nil)
		pathsA := pc.generateNATConnectPathsFromPublicPath(
			publicPath,
			int(stun.MappingEndpointIndependent),
			int(stun.MappingAddressDependent),
		)
		pathsB := pc.generateNATConnectPathsFromPublicPath(
			reversedPublicPath,
			int(stun.MappingAddressDependent),
			int(stun.MappingEndpointIndependent),
		)
		m := map[string]struct{}{}
		for _, path := range pathsA {
			m[fmt.Sprintf("%d:%d", path.LocalAddr.(*net.TCPAddr).Port, path.RemoteAddr.(*net.TCPAddr).Port)] = struct{}{}
		}
		for _, path := range pathsB {
			if _, ok := m[fmt.Sprintf("%d:%d", path.RemoteAddr.(*net.TCPAddr).Port, path.LocalAddr.(*net.TCPAddr).Port)]; ok {
				matchedCount++
				break
			}
		}
	}
	observedProbability := float64(matchedCount) / 1000.0
	if observedProbability < 0.25 {
		t.Errorf("Observed probability is too low: %.2f%%", observedProbability*100)
		return
	}
	t.Logf("Observed probability: %.2f%%", observedProbability*100)
}
