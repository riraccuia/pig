package message

import (
	"net"
	"testing"
)

func TestGenerateICEAnswer(t *testing.T) {
	var hosts []string
	interfaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("failed to get interfaces: %v", err)
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		t.Logf("interface: %s", iface.Name)
		addresses, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			//t.Logf("address: %s", address.String())
			ip, _, err := net.ParseCIDR(address.String())
			if err != nil {
				continue
			}
			if ip.To4() != nil {
				t.Logf("ip: %s", ip.String())
				hosts = append(hosts, ip.String())
			}
		}
	}
}
