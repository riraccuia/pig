// Copyright 2026 Riccardo Raccuia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ice

import (
	"fmt"
	"math/rand"
	"net"
	"sync"

	"github.com/riraccuia/pig/pkg/adapter"
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

// LocalEndpoint represents a local network endpoint.
type LocalEndpoint struct {
	IP  net.IP
	Net *net.IPNet
}

// GetLocalEndpoints returns the local network interfaces and their addresses.
// It returns a slice of LocalEndpoint for each interface.
// Adapters can be excluded by providing a sync.Map with the adapter names as keys,
// the values are ignored.
func _orig_GetLocalEndpoints(bindAdapter string, excludedAdapters *sync.Map) (endpoints []LocalEndpoint, err error) {
	var interfaces []net.Interface
	interfaces, err = net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if excludedAdapters != nil {
			_, ok := excludedAdapters.Load(iface.Name)
			if ok {
				continue
			}
		}
		if bindAdapter != "" && iface.Name != bindAdapter {
			continue
		}
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("failed to get addresses: %w", err)
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
			endpoints = append(endpoints, LocalEndpoint{IP: ip, Net: ipNet})
		}
	}
	return endpoints, nil
}

func GetLocalEndpoints(bindAdapter string, excludedAdapters *sync.Map) (endpoints []LocalEndpoint, err error) {
	var interfaces []net.Interface
	interfaces, err = net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	for _, iface := range interfaces {
		if excludedAdapters != nil {
			_, ok := excludedAdapters.Load(iface.Name)
			if ok {
				continue
			}
		}
		if bindAdapter != "" && iface.Name != bindAdapter {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		ipv4Addr, ipv4Net, err := adapter.GetAdapterAddress(iface.Name, 0x02) // AF_INET
		if err == nil && ipIsValidForEndpoint(ipv4Addr) {
			endpoints = append(endpoints, LocalEndpoint{IP: ipv4Addr, Net: ipv4Net})
		}
		ipv6Addr, ipv6Net, err := adapter.GetAdapterAddress(iface.Name, 0x1e) // AF_INET6
		if err == nil && ipIsValidForEndpoint(ipv6Addr) {
			endpoints = append(endpoints, LocalEndpoint{IP: ipv6Addr, Net: ipv6Net})
		}
	}
	return endpoints, nil
}

func ipIsValidForEndpoint(ip net.IP) bool {
	if ip.IsLoopback() {
		return false
	}
	if ip.IsLinkLocalUnicast() {
		return false
	}
	return true
}
