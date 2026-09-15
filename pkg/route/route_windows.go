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

//go:build windows
// +build windows

package route

import (
	"context"
	"fmt"
	"net"
	"unsafe"

	"github.com/riraccuia/pig/pkg/bindings/win"
	"golang.org/x/sys/windows"
)

type windowsBackend struct {
}

func newBackend() (platformBackend, error) {
	return &windowsBackend{}, nil
}

func (b *windowsBackend) startWatch(ctx context.Context, onChange func(), routeTableV4, routeTableV6 *Table) error {
	return nil
}

func (b *windowsBackend) applyRoute(route *Route) error {
	if route == nil {
		return fmt.Errorf("route is nil")
	}
	if route.Destination == nil {
		return fmt.Errorf("route destination is nil")
	}

	var (
		row windows.MibIpForwardRow2
		err error
	)

	err = b.buildForwardRow(&row, route.Destination, route.Interface, route.Gateway, 0)
	if err != nil {
		return err
	}

	err = win.CreateIpForwardEntry2(&row)
	if err != nil {
		return err
	}

	return nil
}

func (b *windowsBackend) deleteRoute(route *Route) error {
	if route == nil {
		return fmt.Errorf("route is nil")
	}
	if route.Destination == nil {
		return fmt.Errorf("route destination is nil")
	}

	var (
		row windows.MibIpForwardRow2
		err error
	)

	err = b.buildForwardRow(&row, route.Destination, route.Interface, route.Gateway, 0)
	if err != nil {
		return err
	}

	err = win.DeleteIpForwardEntry2(&row)
	if err != nil {
		return err
	}

	return nil
}

func (b *windowsBackend) loadRoutes() ([]*Route, error) {
	return nil, nil
}

func (b *windowsBackend) close() error {
	return nil
}

func (b *windowsBackend) findBestRoute(dst net.IP) (*Route, error) {
	if dst == nil {
		return nil, fmt.Errorf("destination IP is nil")
	}

	// Normalize to canonical family representation.
	dst = normalizeIP(dst)
	if dst == nil {
		return nil, fmt.Errorf("invalid destination IP")
	}

	// Build destination sockaddr for the lookup.
	var dstSock windows.RawSockaddrInet
	var err error

	dstSock, err = sockaddrInetFromIP(dst)
	if err != nil {
		return nil, err
	}

	var bestRoute windows.MibIpForwardRow2
	err = win.GetBestRoute2(nil, 0, nil, &dstSock, 0, &bestRoute, nil)
	if err != nil {
		return nil, err
	}

	// Convert the native row to our Route representation.
	var rt *Route
	rt, err = routeFromRow2(&bestRoute)
	if err != nil {
		return nil, err
	}

	return rt, nil
}

func (b *windowsBackend) buildForwardRow(row *windows.MibIpForwardRow2, destination *net.IPNet, ifaceName string, gateway net.IP, metric uint32) error {
	var (
		prefix  windows.IpAddressPrefix
		nextHop windows.RawSockaddrInet
		err     error
	)

	err = win.InitializeIpForwardEntry(row)
	if err != nil {
		return err
	}

	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return err
		}
		row.InterfaceIndex = uint32(iface.Index)
	}

	if destination != nil {
		prefix, err = ipAddressPrefixFromNet(destination)
		if err != nil {
			return err
		}
		row.DestinationPrefix = prefix
	}

	if gateway != nil {
		nextHop, err = sockaddrInetFromIP(gateway)
		if err != nil {
			return err
		}
		row.NextHop = nextHop
	}

	row.Metric = metric
	row.Protocol = windows.MIB_IPPROTO_NETMGMT
	row.Origin = windows.NlroManual
	return nil
}

// normalizeIP returns the canonical IPv4 or IPv6 form.
func normalizeIP(ip net.IP) net.IP {
	ip4 := ip.To4()
	if ip4 != nil {
		return ip4
	}
	return ip.To16()
}

// ipAddressPrefixFromNet converts an IPNet to a Windows IpAddressPrefix.
func ipAddressPrefixFromNet(ipNet *net.IPNet) (windows.IpAddressPrefix, error) {
	var prefix windows.IpAddressPrefix
	if ipNet == nil {
		return prefix, fmt.Errorf("destination network is nil")
	}

	var (
		ones int
		bits int
	)
	ones, bits = ipNet.Mask.Size()
	if ones < 0 || bits == 0 {
		return prefix, fmt.Errorf("invalid destination mask")
	}

	var networkIP net.IP
	networkIP = ipNet.IP.Mask(ipNet.Mask)
	if networkIP == nil {
		return prefix, fmt.Errorf("invalid destination IP")
	}

	var addr windows.RawSockaddrInet
	var err error
	addr, err = sockaddrInetFromIP(networkIP)
	if err != nil {
		return prefix, err
	}

	prefix.Prefix = addr
	prefix.PrefixLength = uint8(ones)
	return prefix, nil
}

// sockaddrInetFromIP builds a Windows sockaddr for the given IP.
func sockaddrInetFromIP(ip net.IP) (windows.RawSockaddrInet, error) {
	var addr windows.RawSockaddrInet
	ip4 := ip.To4()
	if ip4 != nil {
		addr4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&addr))
		addr4.Family = windows.AF_INET
		addr4.Port = 0
		addr4.Addr[0] = ip4[0]
		addr4.Addr[1] = ip4[1]
		addr4.Addr[2] = ip4[2]
		addr4.Addr[3] = ip4[3]
		return addr, nil
	}

	ip6 := ip.To16()
	if ip6 == nil {
		return addr, fmt.Errorf("invalid IP")
	}

	addr6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&addr))
	addr6.Family = windows.AF_INET6
	addr6.Port = 0
	copy(addr6.Addr[:], ip6)
	return addr, nil
}

// routeFromRow2 converts a Windows route row to a Route.
func routeFromRow2(row *windows.MibIpForwardRow2) (*Route, error) {
	if row == nil {
		return nil, fmt.Errorf("route row is nil")
	}

	var dstIP net.IP
	dstIP = ipFromSockaddr(row.DestinationPrefix.Prefix)
	if dstIP == nil {
		return nil, fmt.Errorf("route destination is nil")
	}

	bits := 128
	if dstIP.To4() != nil {
		bits = 32
	}

	mask := net.CIDRMask(int(row.DestinationPrefix.PrefixLength), bits)
	if mask == nil {
		return nil, fmt.Errorf("invalid destination mask")
	}

	var route Route
	route.Destination = &net.IPNet{
		IP:   dstIP,
		Mask: mask,
	}
	route.Gateway = ipFromSockaddr(row.NextHop)

	if row.InterfaceIndex != 0 {
		iface, err := net.InterfaceByIndex(int(row.InterfaceIndex))
		if err == nil {
			route.Interface = iface.Name
		}
	}

	return &route, nil
}

// ipFromSockaddr converts a Windows sockaddr to net.IP.
func ipFromSockaddr(addr windows.RawSockaddrInet) net.IP {
	if addr.Family == windows.AF_INET {
		addr4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&addr))
		return net.IPv4(addr4.Addr[0], addr4.Addr[1], addr4.Addr[2], addr4.Addr[3]).To4()
	}

	if addr.Family == windows.AF_INET6 {
		addr6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&addr))
		return net.IP(addr6.Addr[:]).To16()
	}

	return nil
}
