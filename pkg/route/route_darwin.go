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

package route

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

type darwinBackend struct {
	socketV4 int
	socketV6 int
	onChange func()
}

func openRouteSocket(family int) (int, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, family)
	if err != nil {
		return 0, fmt.Errorf("failed to create route socket: %w", err)
	}
	return fd, nil
}

func newBackend() (platformBackend, error) {
	fdV4, err := openRouteSocket(unix.AF_INET)
	if err != nil {
		unix.Close(fdV4)
		return nil, err
	}

	fdV6, err := openRouteSocket(unix.AF_INET6)
	if err != nil {
		unix.Close(fdV4)
		return nil, err
	}

	backend := &darwinBackend{
		socketV4: fdV4,
		socketV6: fdV6,
	}

	return backend, nil
}

func (b *darwinBackend) startWatch(ctx context.Context, onChange func(), routeTableV4, routeTableV6 *Table) error {
	b.onChange = onChange
	go b.monitorRoutes(routeTableV4, routeTableV6)
	return nil
}

func (b *darwinBackend) close() error {
	if b.socketV4 != 0 {
		err := unix.Close(b.socketV4)
		b.socketV4 = 0
		if err != nil {
			return err
		}
	}

	if b.socketV6 != 0 {
		err := unix.Close(b.socketV6)
		b.socketV6 = 0
		return err
	}

	return nil
}

func (b *darwinBackend) routeSocketForIP(ip net.IP) (int, error) {
	if ip.To4() != nil {
		if b.socketV4 == 0 {
			return 0, fmt.Errorf("IPv4 route socket is closed")
		}
		return b.socketV4, nil
	}
	if b.socketV6 == 0 {
		return 0, fmt.Errorf("IPv6 route socket is closed")
	}
	return b.socketV6, nil
}

func (b *darwinBackend) routeSocketForRoute(rt *Route) (int, error) {
	return b.routeSocketForIP(rt.Destination.IP)
}

func (b *darwinBackend) applyRoute(rt *Route) error {
	msg, err := b.buildRouteMessage(rt, unix.RTM_ADD, 0)
	if err != nil {
		return fmt.Errorf("failed to build route message: %w", err)
	}

	socket, err := b.routeSocketForRoute(rt)
	if err != nil {
		return err
	}

	_, err = unix.Write(socket, msg)
	if err != nil {
		return err //fmt.Errorf("failed to send route message: %w", err)
	}

	return nil
}

func (b *darwinBackend) deleteRoute(rt *Route) error {
	msg, err := b.buildRouteMessageRaw(rt, unix.RTM_DELETE, 0)
	if err != nil {
		return fmt.Errorf("failed to build route message: %w", err)
	}

	socket, err := b.routeSocketForRoute(rt)
	if err != nil {
		return err
	}

	_, err = unix.Write(socket, msg)
	if err != nil {
		return fmt.Errorf("failed to send route message: %w", err)
	}

	return nil
}

func (b *darwinBackend) loadRoutes() ([]*Route, error) {
	msgs, err := b.getRouteMessages()
	if err != nil {
		return nil, err
	}

	var routes []*Route
	b.processRouteMessages(msgs, func(rt *Route, rm *route.RouteMessage) {
		if rm.Flags&unix.RTF_LLINFO != 0 {
			routes = append(routes, rt)
			return
		}
		if rm.Flags&(unix.RTF_WASCLONED) != 0 {
			return
		}
		if rm.Flags&unix.RTF_IFSCOPE != 0 {
			return
		}
		routes = append(routes, rt)
	})

	return routes, nil
}

func (b *darwinBackend) getRouteMessages() ([]route.Message, error) {
	rib, err := route.FetchRIB(unix.AF_UNSPEC, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch routing table: %w", err)
	}

	// Parse the route messages
	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, fmt.Errorf("failed to parse route messages: %w", err)
	}

	return msgs, nil
}

func (b *darwinBackend) processRouteMessages(msgs []route.Message, fn func(*Route, *route.RouteMessage)) {
	for _, msg := range msgs {
		rm, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}

		rt, err := b.convertRouteMessage(rm)
		if err != nil {
			continue
		}

		fn(rt, rm)
	}
}

func (b *darwinBackend) convertRouteMessage(rm *route.RouteMessage) (*Route, error) {
	var (
		rt            = &Route{}
		destination   net.IP
		gateway       net.IP
		netmask       net.IPMask
		interfaceName string
		linkAddr      net.HardwareAddr
	)

	// Parse addresses from the route message
	for i, addr := range rm.Addrs {
		if addr == nil {
			continue
		}

		var (
			ip   net.IP
			mask net.IPMask
		)

		switch a := addr.(type) {
		case *route.Inet4Addr:
			ip = net.IP(a.IP[:]).To4()
			mask = net.IPMask(a.IP[:])
		case *route.Inet6Addr:
			ip = net.IP(a.IP[:]).To16()
			mask = net.IPMask(a.IP[:])
		case *route.LinkAddr:
			linkAddr = net.HardwareAddr(a.Addr[:])
			continue
		}
		if i == 0 { // First address is destination
			destination = ip
		}
		if i == 1 { // Second address is gateway
			gateway = ip
		}
		if i == 2 { // Third address is netmask
			netmask = mask
		}
	}

	// Get interface name from index
	if iface, err := net.InterfaceByIndex(rm.Index); err == nil {
		interfaceName = iface.Name
	}

	// Validate we have at least a destination
	if destination == nil {
		return rt, fmt.Errorf("route missing destination")
	}

	// Set default netmask if not provided
	if netmask == nil {
		switch {
		case destination.To4() != nil:
			netmask = net.CIDRMask(32, 32) // /32 for IPv4 host
		case destination.To16() != nil:
			netmask = net.CIDRMask(128, 128) // /128 for IPv6 host
		default:
			return rt, fmt.Errorf("route missing netmask")
		}
	}

	// Create the route
	rt.Destination = &net.IPNet{
		IP:   destination,
		Mask: netmask,
	}
	rt.Gateway = gateway
	rt.Interface = interfaceName
	rt.LinkAddr = linkAddr

	return rt, nil
}

func (b *darwinBackend) monitorRoutes(routeTableV4, routeTableV6 *Table) {
	monSocket, err := openRouteSocket(0)
	if err != nil {
		return
	}

	buf := make([]byte, 4096)

	err = unix.SetNonblock(monSocket, true)
	if err != nil {
		return
	}

	for {
		n, err := unix.Read(monSocket, buf)
		if err != nil {
			// Check if it's a "would block" error (no data available)
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			// Other errors - socket might be closed
			return
		}

		if n == 0 {
			continue
		}

		b.parseRouteMessage(buf[:n], routeTableV4, routeTableV6)
	}
}

func (b *darwinBackend) parseRouteMessage(msg []byte, routeTableV4, routeTableV6 *Table) {
	msgs, err := route.ParseRIB(route.RIBTypeRoute, msg)
	if err != nil {
		msgs, err = route.ParseRIB(route.RIBTypeInterface, msg)
	}

	if err != nil {
		return
	}

	for _, msg := range msgs {
		switch rm := msg.(type) {
		case *route.RouteMessage:
			b.handleRouteMessage(rm, routeTableV4, routeTableV6)
		}
	}
}

func (b *darwinBackend) handleRouteMessage(msg *route.RouteMessage, routeTableV4, routeTableV6 *Table) {
	if msg.Type != unix.RTM_ADD && msg.Type != unix.RTM_DELETE {
		return
	}

	rt, err := b.convertRouteMessage(msg)
	if err != nil {
		return
	}

	//rtFamily := unix.AF_INET
	routeTable := routeTableV4
	if !rt.Is4() {
		//rtFamily = unix.AF_INET6
		routeTable = routeTableV6
	}

	isLLInfo := msg.Flags&unix.RTF_LLINFO != 0

	if !isLLInfo && msg.Flags&unix.RTF_IFSCOPE != 0 {
		return
	}

	// isDefault := routeToPrefixBits(rt) == 0 && isValidGateway(rt.Gateway, rm.Flags)

	if msg.Type == unix.RTM_ADD {
		if !isLLInfo && msg.Flags&(unix.RTF_WASCLONED) != 0 {
			return
		}
		systemRoute, err := b.getSystemRoute(rt.Destination.IP)
		if err != nil {
			// it does not seem that the route was added to the system route table
			return
		}
		rt = systemRoute
		routeTable.Insert(rt)
		b.onChange()
		return
	}

	// it's a delete message

	routeTable.Remove(rt)
	b.onChange()
}

func (b *darwinBackend) createInetAddr(ip net.IP) route.Addr {
	if ip.To4() != nil {
		var ip4 [4]byte
		copy(ip4[:], ip.To4())
		return &route.Inet4Addr{IP: ip4}
	}
	var ip6 [16]byte
	copy(ip6[:], ip.To16())
	return &route.Inet6Addr{IP: ip6}
}

func (b *darwinBackend) calculateNetworkAddress(ipnet *net.IPNet) net.IP {
	ones, bits := ipnet.Mask.Size()
	if ones == bits {
		return ipnet.IP
	}
	return ipnet.IP.Mask(ipnet.Mask)
}

func linkAddrForInterface(name string, index int) route.Addr {
	return &route.LinkAddr{
		Index: index,
		Name:  name,
	}
}

func (b *darwinBackend) buildRouteMessageRaw(rt *Route, msgType int, flags int) ([]byte, error) {
	var (
		addrs = make([]route.Addr, unix.RTAX_MAX)
		msg   = &route.RouteMessage{
			Type:    msgType,
			Version: unix.RTM_VERSION,
			ID:      uintptr(os.Getpid()),
			Seq:     1,
		}
	)

	if rt.Destination == nil {
		return nil, fmt.Errorf("route destination is nil")
	}

	destinationIP := b.calculateNetworkAddress(rt.Destination)
	if destinationIP == nil {
		return nil, fmt.Errorf("invalid route destination: %v", rt.Destination.String())
	}

	addrs[unix.RTAX_DST] = b.createInetAddr(destinationIP)

	if rt.Gateway != nil {
		addrs[unix.RTAX_GATEWAY] = b.createInetAddr(rt.Gateway)
	}

	maskIP := net.IP(rt.Destination.Mask)
	addrs[unix.RTAX_NETMASK] = b.createInetAddr(maskIP)

	if rt.Interface != "" {
		iface, err := net.InterfaceByName(rt.Interface)
		if err != nil {
			return nil, fmt.Errorf("interface %s not found: %w", rt.Interface, err)
		}
		msg.Index = iface.Index
		addrs[unix.RTAX_IFP] = linkAddrForInterface(rt.Interface, iface.Index)
	}

	msg.Flags |= flags | unix.RTF_UP | unix.RTF_STATIC | unix.RTF_PRCLONING

	msg.Addrs = addrs

	return msg.Marshal()
}

func (b *darwinBackend) buildRouteMessage(rt *Route, msgType int, flags int) ([]byte, error) {

	switch {
	case rt.Gateway != nil:
		flags |= unix.RTF_GATEWAY
	default:
		var zeroAddr net.IP = net.IPv4zero
		if !rt.Is4() {
			zeroAddr = net.IPv6zero
		}
		rt.Gateway = zeroAddr
	}

	return b.buildRouteMessageRaw(rt, msgType, flags)
}

func isValidGateway(ip net.IP, routeFlags int) bool {
	if ip == nil {
		return false
	}
	if ip.IsLoopback() {
		return false
	}
	if ip.To4() != nil && ip.IsLinkLocalUnicast() {
		return false
	}
	if routeFlags&unix.RTF_IFSCOPE != 0 {
		// e.g. "default fe80::%utun0"
		return false
	}
	return true
}

func (b *darwinBackend) getSystemRoute(dst net.IP) (*Route, error) {
	if dst == nil {
		return nil, fmt.Errorf("destination IP is nil")
	}

	isV4 := dst.To4() != nil
	if isV4 {
		dst = dst.To4()
	}
	if !isV4 {
		dst = dst.To16()
	}
	if dst == nil {
		return nil, fmt.Errorf("invalid destination IP")
	}

	family := unix.AF_INET6
	if isV4 {
		family = unix.AF_INET
	}

	socket, err := openRouteSocket(family)
	if err != nil {
		return nil, err
	}
	defer unix.Close(socket)

	msg := &route.RouteMessage{
		Type:    unix.RTM_GET,
		Version: unix.RTM_VERSION,
		ID:      uintptr(os.Getpid()),
		Seq:     1,
		Addrs: []route.Addr{
			unix.RTAX_DST: b.createInetAddr(dst),
		},
	}

	wireMsg, err := msg.Marshal()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal route message: %w", err)
	}

	_, err = unix.Write(socket, wireMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to send route query: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := unix.Read(socket, buf)
	if err != nil {
		return nil, fmt.Errorf("failed to read route response: %w", err)
	}
	if n == 0 {
		return nil, fmt.Errorf("empty route response")
	}

	msgs, err := route.ParseRIB(route.RIBTypeRoute, buf[:n])
	if err != nil {
		return nil, fmt.Errorf("failed to parse route response: %w", err)
	}

	for _, parsed := range msgs {
		rm, ok := parsed.(*route.RouteMessage)
		if !ok {
			continue
		}
		if rm.Type != unix.RTM_GET {
			continue
		}
		if rm.ID != msg.ID || rm.Seq != msg.Seq {
			continue
		}
		rt, err := b.convertRouteMessage(rm)
		if err != nil {
			return nil, err
		}
		return rt, nil
	}

	return nil, fmt.Errorf("no route response for %s", dst.String())
}

func routeFromNeighbor(target net.IP) (*Route, error) {
	return nil, errors.New("not implemented")
}
