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
	onChange     func()
	notifyHandle windows.Handle
	callback     uintptr // kept alive for NotifyRouteChange2
}

func newBackend() (platformBackend, error) {
	return &windowsBackend{}, nil
}

func (b *windowsBackend) startWatch(ctx context.Context, onChange func(), routeTableV4, routeTableV6 *Table) error {
	b.onChange = onChange

	b.callback = windows.NewCallback(func(callerContext unsafe.Pointer, row *windows.MibIpForwardRow2, notificationType uint32) uintptr {
		return b.routeChangeCallback(callerContext, row, notificationType, routeTableV4, routeTableV6)
	})
	handle, err := win.NotifyRouteChange2(windows.AF_UNSPEC, b.callback, nil, false)
	if err != nil {
		return err
	}
	b.notifyHandle = handle
	return nil
}

func (b *windowsBackend) routeChangeCallback(callerContext unsafe.Pointer, row *windows.MibIpForwardRow2, notificationType uint32, routeTableV4, routeTableV6 *Table) uintptr {
	if row == nil {
		return 0
	}
	switch notificationType {
	case windows.MibInitialNotification:
		return 0
	case windows.MibAddInstance, windows.MibParameterNotification:
		b.handleRouteAddOrUpdate(row, routeTableV4, routeTableV6)
	case windows.MibDeleteInstance:
		b.handleRouteDelete(row, routeTableV4, routeTableV6)
	}
	return 0
}

func (b *windowsBackend) handleRouteAddOrUpdate(row *windows.MibIpForwardRow2, routeTableV4, routeTableV6 *Table) {
	// NotifyRouteChange2 passes an incomplete row; query full details first.
	// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2
	full := windows.MibIpForwardRow2{
		InterfaceLuid:     row.InterfaceLuid,
		InterfaceIndex:    row.InterfaceIndex,
		DestinationPrefix: row.DestinationPrefix,
		NextHop:           row.NextHop,
	}
	if err := windows.GetIpForwardEntry2(&full); err != nil {
		return
	}
	rt, err := routeFromForwardRow(&full)
	if err != nil {
		return
	}
	routeTable := routeTableV4
	if !rt.Is4() {
		routeTable = routeTableV6
	}
	routeTable.Insert(rt)
	b.onChange()
}

func (b *windowsBackend) handleRouteDelete(row *windows.MibIpForwardRow2, routeTableV4, routeTableV6 *Table) {
	// Route is already gone from the OS table; use the callback key fields only.
	rt, err := routeFromForwardRow(row)
	if err != nil {
		return
	}
	routeTable := routeTableV4
	if !rt.Is4() {
		routeTable = routeTableV6
	}
	routeTable.Remove(rt)
	b.onChange()
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
	table, err := win.GetIpForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return nil, err
	}
	defer win.FreeMibTable(unsafe.Pointer(table))

	var routes []*Route
	rows := table.Rows()
	for i := range rows {
		rt, err := routeFromForwardRow(&rows[i])
		if err != nil {
			continue
		}
		if rt.Destination == nil {
			continue
		}
		routes = append(routes, rt)
	}
	return routes, nil
}

func (b *windowsBackend) close() error {
	if b.notifyHandle == 0 {
		return nil
	}
	// Must not be called from the NotifyRouteChange2 callback thread (deadlock).
	err := win.CancelMibChangeNotify2(b.notifyHandle)
	b.notifyHandle = 0
	return err
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

// routeFromForwardRow converts a Windows route row to a Route.
func routeFromForwardRow(row *windows.MibIpForwardRow2) (*Route, error) {
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

	nextHop := ipFromSockaddr(row.NextHop)
	if nextHop.Equal(net.IPv4zero) || nextHop.Equal(net.IPv6zero) {
		nextHop = nil
	}

	switch {
	case nextHop == nil || row.Loopback == 1:
		//route.LinkAddr = getLinkAddr(row.InterfaceLuid, row.InterfaceIndex, dstIP)
		route.Gateway = nil
	default:
		route.Gateway = nextHop
	}

	if row.InterfaceIndex != 0 {
		iface, err := net.InterfaceByIndex(int(row.InterfaceIndex))
		if err == nil {
			route.Interface = iface.Name
		}
	}

	return &route, nil
}

func routeFromNeighbor(target net.IP) (*Route, error) {
	var (
		row                = &win.MibIpNetRow2{}
		prefixLength, bits int
	)
	switch {
	case target.To4() != nil:
		addr4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
		addr4.Family = windows.AF_INET
		copy(addr4.Addr[:], target.To4())
		prefixLength, bits = 32, 32
	case target.To16() != nil:
		addr6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&row.Address))
		addr6.Family = windows.AF_INET6
		copy(addr6.Addr[:], target.To16())
		prefixLength, bits = 128, 128
	}
	err := win.GetIpNetEntry2(row)
	if err != nil {
		return nil, err
	}

	switch row.State {
	case win.NlnsUnreachable, win.NlnsStale, win.NlnsIncomplete:
		return nil, fmt.Errorf("neighbor is unreachable, stale, or incomplete")
	default:
		// go on
	}

	rt := &Route{
		Destination: &net.IPNet{
			IP:   target,
			Mask: net.CIDRMask(prefixLength, bits),
		},
		LinkAddr: net.HardwareAddr(row.PhysicalAddress[:row.PhysicalAddressLength]),
	}

	if rt.LinkAddr == nil {
		return nil, fmt.Errorf("link address is nil")
	}

	ifName, err := win.ConvertInterfaceLuidToAlias(row.InterfaceLuid)
	if err != nil {
		return nil, err
	}

	rt.Interface = ifName
	return rt, nil
}

// ipFromSockaddr converts a Windows sockaddr to net.IP.
func ipFromSockaddr(addr windows.RawSockaddrInet) net.IP {
	if addr.Family == windows.AF_INET {
		addr4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&addr))
		return net.IPv4(addr4.Addr[0], addr4.Addr[1], addr4.Addr[2], addr4.Addr[3]).To4()
	}

	if addr.Family == windows.AF_INET6 {
		addr6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&addr))
		// Copy: To16() on a 16-byte IP returns the same slice, which would alias addr.
		return append(net.IP(nil), addr6.Addr[:]...)
	}

	return nil
}
