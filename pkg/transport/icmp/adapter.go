package icmp

import (
	"fmt"
	"net"
)

func getAdapterAddr(adapterName string) (*net.IPAddr, *net.Interface, error) {
	iface, err := net.InterfaceByName(adapterName)
	if err != nil {
		return nil, iface, fmt.Errorf("failed to get interface: %w", err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, iface, fmt.Errorf("failed to get addresses: %w", err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return &net.IPAddr{IP: ipnet.IP}, iface, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no valid address found")
}
