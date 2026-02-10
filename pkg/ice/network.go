package ice

import (
	"fmt"
	"math/rand"
	"net"
)

// AddressFrom creates a net.Addr from a network, IP and port.
// If the port is 0, it will be randomly assigned between 1024 and 65535.
func AddressFrom(network string, ip net.IP, port int) (addr net.Addr) {
	if port == 0 {
		port = rand.Intn(65535-1024) + 1024
	}
	switch network {
	case "udp":
		addr = &net.UDPAddr{IP: ip, Port: port}
	case "tcp":
		addr = &net.TCPAddr{IP: ip, Port: port}
	case "icmp":
		addr = &net.IPAddr{IP: ip}
	}
	return
}

// GetLocalNetworks returns the local network interfaces and their addresses.
// It returns a list of IPNet and IP addresses for each interface, each slice
// index corresponds to the same interface index. The two slices are guaranteed
// to have the same length.
func GetLocalNetworks(bindAdapter string) (ipNets []*net.IPNet, ips []net.IP, err error) {
	var interfaces []net.Interface
	interfaces, err = net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if bindAdapter != "" && iface.Name != bindAdapter {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get addresses: %w", err)
		}
		for _, address := range addresses {
			var (
				ip    net.IP
				ipNet *net.IPNet
			)
			ip, ipNet, err = net.ParseCIDR(address.String())
			if err != nil {
				continue
			}
			if ipNet.IP.IsLoopback() {
				continue
			}
			if ipNet.IP.IsLinkLocalUnicast() {
				continue
			}
			/*if ip.To4() != nil {
				continue
			}*/
			if ip == nil {
				continue
			}
			ipNets = append(ipNets, ipNet)
			ips = append(ips, ip)
		}
	}
	return ipNets, ips, nil
}
