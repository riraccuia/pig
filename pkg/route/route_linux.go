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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

type linuxBackend struct {
	syncSocket int
	syncPort   uint32
	monSocket  int
	syncMu     sync.Mutex
	onChange   func()
}

type netlinkRoute struct {
	hdr   syscall.NlMsghdr
	msg   syscall.RtMsg
	attrs map[int][]byte
}

func openNetlinkSocket(groups uint32) (int, uint32, error) {
	// open raw socket for the NETLINK_ROUTE protocol
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW, unix.NETLINK_ROUTE)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to create netlink socket: %w", err)
	}
	sa := &unix.SockaddrNetlink{
		Family: unix.AF_NETLINK,
		Groups: groups,
	}
	// bind current process to the netlink socket
	if err := unix.Bind(fd, sa); err != nil {
		unix.Close(fd)
		return 0, 0, fmt.Errorf("failed to bind netlink socket: %w", err)
	}
	lsa, err := unix.Getsockname(fd)
	if err != nil {
		unix.Close(fd)
		return 0, 0, fmt.Errorf("failed to get netlink socket port: %w", err)
	}
	lsanl, ok := lsa.(*unix.SockaddrNetlink)
	if !ok {
		unix.Close(fd)
		return 0, 0, unix.EINVAL
	}
	return fd, lsanl.Pid, nil
}

func newBackend() (platformBackend, error) {
	syncSocket, syncPort, err := openNetlinkSocket(0)
	if err != nil {
		return nil, err
	}
	return &linuxBackend{syncSocket: syncSocket, syncPort: syncPort}, nil
}

func (b *linuxBackend) startWatch(ctx context.Context, onChange func(), routeTableV4, routeTableV6 *Table) error {
	monSocket, _, err := openNetlinkSocket(unix.RTMGRP_IPV4_ROUTE | unix.RTMGRP_IPV6_ROUTE)
	if err != nil {
		return err
	}
	b.monSocket = monSocket
	b.onChange = onChange
	go b.monitorRoutes(routeTableV4, routeTableV6)
	return nil
}

func (b *linuxBackend) close() error {
	if b.monSocket != 0 {
		err := unix.Close(b.monSocket)
		b.monSocket = 0
		if err != nil {
			return err
		}
	}
	if b.syncSocket != 0 {
		err := unix.Close(b.syncSocket)
		b.syncSocket = 0
		return err
	}
	return nil
}

func (b *linuxBackend) applyRoute(rt *Route) error {
	req, err := b.buildRouteNetlinkMessage(rt, unix.RTM_NEWROUTE, unix.NLM_F_ACK|unix.NLM_F_CREATE)
	if err != nil {
		return fmt.Errorf("failed to build route message: %w", err)
	}
	return b.netlinkTransact(req)
}

func (b *linuxBackend) deleteRoute(rt *Route) error {
	req, err := b.buildRouteNetlinkMessageRaw(rt, unix.RTM_DELROUTE, unix.NLM_F_ACK)
	if err != nil {
		return fmt.Errorf("failed to build route message: %w", err)
	}
	return b.netlinkTransact(req)
}

func (b *linuxBackend) loadRoutes() ([]*Route, error) {
	routes, err := b.getRouteMessages()
	if err != nil {
		return nil, err
	}
	var out []*Route
	for _, nr := range routes {
		if nr.msg.Table != unix.RT_TABLE_MAIN {
			continue
		}
		rt, err := b.convertNetlinkRoute(&nr)
		if err != nil {
			continue
		}
		if !includeLoadedRoute(&nr.msg) {
			continue
		}
		out = append(out, rt)
	}
	return out, nil
}

func (b *linuxBackend) getRouteMessages() ([]netlinkRoute, error) {
	tab, err := syscall.NetlinkRIB(unix.RTM_GETROUTE, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch routing table: %w", err)
	}
	return parseNetlinkRoutes(tab)
}

func (b *linuxBackend) monitorRoutes(routeTableV4, routeTableV6 *Table) {
	buf := make([]byte, unix.Getpagesize())
	for {
		n, err := unix.Read(b.monSocket, buf)
		if err != nil {
			if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
				continue
			}
			return
		}
		if n == 0 {
			continue
		}
		b.parseRouteMessage(buf[:n], routeTableV4, routeTableV6)
	}
}

func (b *linuxBackend) parseRouteMessage(msg []byte, routeTableV4, routeTableV6 *Table) {
	routes, err := parseNetlinkRoutes(msg)
	if err != nil {
		return
	}
	for i := range routes {
		b.handleRouteMessage(&routes[i], routeTableV4, routeTableV6)
	}
}

func (b *linuxBackend) handleRouteMessage(nr *netlinkRoute, routeTableV4, routeTableV6 *Table) {
	if nr.hdr.Type != unix.RTM_NEWROUTE && nr.hdr.Type != unix.RTM_DELROUTE {
		return
	}
	if nr.msg.Table != unix.RT_TABLE_MAIN {
		return
	}
	rt, err := b.convertNetlinkRoute(nr)
	if err != nil {
		return
	}
	routeTable := routeTableV4
	if !rt.Is4() {
		routeTable = routeTableV6
	}
	isLinkNeighbor := isLinkScopeNeighbor(&nr.msg)
	if !isLinkNeighbor && nr.msg.Scope == unix.RT_SCOPE_LINK {
		return
	}
	if nr.hdr.Type == unix.RTM_NEWROUTE {
		if !isLinkNeighbor && nr.msg.Type == unix.RTN_LOCAL {
			return
		}
		systemRoute, err := b.getSystemRoute(rt.Destination.IP)
		if err != nil {
			return
		}
		rt = systemRoute
		routeTable.Insert(rt)
		b.onChange()
		routeTable.Walk(func(r *Route) {
			fmt.Printf("Dump route: %+v\n", r)
		})
		return
	}
	routeTable.Remove(rt)
	routeTable.Walk(func(r *Route) {
		fmt.Printf("Dump route: %+v\n", r)
	})
	b.onChange()
}

func (b *linuxBackend) convertNetlinkRoute(nr *netlinkRoute) (*Route, error) {
	dstRaw := nr.attrs[unix.RTA_DST]
	var (
		destination net.IP
		gateway     net.IP
		bits        int
	)
	switch nr.msg.Family {
	case unix.AF_INET:
		bits = 32
		destination = net.IPv4zero
		if len(dstRaw) >= 4 {
			destination = net.IP(dstRaw[:4]).To4()
		}
	case unix.AF_INET6:
		bits = 128
		destination = net.IPv6zero
		if len(dstRaw) >= 16 {
			destination = net.IP(dstRaw[:16]).To16()
		}
	default:
		return nil, fmt.Errorf("unsupported address family")
	}
	prefixLen := int(nr.msg.Dst_len)
	mask := net.CIDRMask(prefixLen, bits)
	if mask == nil {
		return nil, fmt.Errorf("invalid route prefix")
	}
	gwRaw := nr.attrs[unix.RTA_GATEWAY]
	switch nr.msg.Family {
	case unix.AF_INET:
		if len(gwRaw) >= 4 {
			gateway = net.IP(gwRaw[:4]).To4()
		}
	case unix.AF_INET6:
		if len(gwRaw) >= 16 {
			gateway = net.IP(gwRaw[:16]).To16()
		}
	}
	var (
		interfaceName string
		oif           int
	)
	if oifRaw := attrUint32(nr.attrs[unix.RTA_OIF]); oifRaw != 0 {
		oif = int(oifRaw)
		if iface, err := net.InterfaceByIndex(oif); err == nil {
			interfaceName = iface.Name
		}
	}
	var linkAddr net.HardwareAddr
	if isLinkScopeNeighbor(&nr.msg) && oif != 0 {
		linkAddr = b.lookupNeighborLLAddr(destination, oif, nr.msg.Family)
	}
	return &Route{
		Destination: &net.IPNet{IP: destination, Mask: mask},
		Gateway:     gateway,
		Interface:   interfaceName,
		LinkAddr:    linkAddr,
	}, nil
}

func (b *linuxBackend) lookupNeighborLLAddr(ip net.IP, ifindex int, family uint8) net.HardwareAddr {
	dst := ip.To4()
	if family == unix.AF_INET6 {
		dst = ip.To16()
	}
	if dst == nil {
		return nil
	}
	seq := uint32(1)
	ndmsg := unix.NdMsg{
		Family:  family,
		Ifindex: int32(ifindex),
	}
	req, err := encodeNetlinkNeigh(unix.RTM_GETNEIGH, unix.NLM_F_REQUEST, seq, b.syncPort, ndmsg, []rtAttrEntry{{unix.NDA_DST, dst}})
	if err != nil {
		return nil
	}
	tab, err := b.netlinkExchange(req, seq, netlinkWaitNeigh)
	if err != nil {
		return nil
	}
	attrs, ok := parseNetlinkNeighAttrs(tab)
	if !ok {
		return nil
	}
	llRaw := attrs[unix.NDA_LLADDR]
	if len(llRaw) == 0 {
		return nil
	}
	return net.HardwareAddr(llRaw)
}

func (b *linuxBackend) buildRouteNetlinkMessage(rt *Route, nlType, flags uint16) ([]byte, error) {
	if rt.Gateway == nil {
		zeroAddr := net.IPv4zero
		if !rt.Is4() {
			zeroAddr = net.IPv6zero
		}
		rt.Gateway = zeroAddr
	}
	return b.buildRouteNetlinkMessageRaw(rt, nlType, flags)
}

func (b *linuxBackend) buildRouteNetlinkMessageRaw(rt *Route, nlType uint16, flags uint16) ([]byte, error) {
	if rt.Destination == nil {
		return nil, fmt.Errorf("route destination is nil")
	}
	destinationIP := calculateNetworkAddress(rt.Destination)
	if destinationIP == nil {
		return nil, fmt.Errorf("invalid route destination: %v", rt.Destination.String())
	}
	len := routeToPrefixBits(rt)
	family := unix.AF_INET6
	dstBytes := destinationIP.To16()
	if rt.Is4() {
		family = unix.AF_INET
		dstBytes = destinationIP.To4()
	}
	if dstBytes == nil {
		return nil, fmt.Errorf("invalid route destination IP")
	}
	rtmsg := unix.RtMsg{
		Family:   uint8(family),
		Dst_len:  uint8(len),
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_STATIC,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}
	attrs := []rtAttrEntry{
		{unix.RTA_DST, dstBytes},
	}
	if rt.Gateway != nil && !rt.Gateway.Equal(net.IPv4zero) && !rt.Gateway.Equal(net.IPv6zero) {
		gw := rt.Gateway.To16()
		if rt.Is4() {
			gw = rt.Gateway.To4()
		}
		if gw != nil {
			attrs = append(attrs, rtAttrEntry{unix.RTA_GATEWAY, gw})
		}
	}
	if rt.Interface != "" {
		iface, err := net.InterfaceByName(rt.Interface)
		if err != nil {
			return nil, fmt.Errorf("interface %s not found: %w", rt.Interface, err)
		}
		oif := make([]byte, 4)
		binary.NativeEndian.PutUint32(oif, uint32(iface.Index))
		attrs = append(attrs, rtAttrEntry{unix.RTA_OIF, oif})
	}
	return encodeNetlinkRoute(nlType, unix.NLM_F_REQUEST|flags, 1, b.syncPort, rtmsg, attrs)
}

func (b *linuxBackend) getSystemRoute(dst net.IP) (*Route, error) {
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
	dstLen := uint8(128)
	if isV4 {
		family = unix.AF_INET
		dstLen = 32
	}
	seq := uint32(1)
	rtmsg := unix.RtMsg{
		Family:   uint8(family),
		Dst_len:  dstLen,
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_STATIC,
		Scope:    unix.RT_SCOPE_UNIVERSE,
		Type:     unix.RTN_UNICAST,
	}
	req, err := encodeNetlinkRoute(unix.RTM_GETROUTE, unix.NLM_F_REQUEST, seq, b.syncPort, rtmsg, []rtAttrEntry{{unix.RTA_DST, dst}})
	if err != nil {
		return nil, err
	}
	tab, err := b.netlinkExchange(req, seq, netlinkWaitRoute)
	if err != nil {
		return nil, fmt.Errorf("failed to query route: %w", err)
	}
	routes, err := parseNetlinkRoutes(tab)
	if err != nil {
		return nil, err
	}
	for i := range routes {
		if routes[i].hdr.Type != unix.RTM_NEWROUTE {
			continue
		}
		rt, err := b.convertNetlinkRoute(&routes[i])
		if err != nil {
			return nil, err
		}
		return rt, nil
	}
	return nil, fmt.Errorf("no route response for %s", dst.String())
}

func (b *linuxBackend) netlinkTransact(req []byte) error {
	seq := binary.NativeEndian.Uint32(req[8:12])
	_, err := b.netlinkExchange(req, seq, netlinkWaitAck)
	return err
}

type netlinkWaitMode int

const (
	netlinkWaitAck netlinkWaitMode = iota
	netlinkWaitRoute
	netlinkWaitNeigh
)

func (b *linuxBackend) netlinkExchange(req []byte, seq uint32, mode netlinkWaitMode) ([]byte, error) {
	b.syncMu.Lock()
	defer b.syncMu.Unlock()

	sa := &unix.SockaddrNetlink{Family: unix.AF_NETLINK}
	if err := unix.Sendto(b.syncSocket, req, 0, sa); err != nil {
		return nil, fmt.Errorf("failed to send netlink message: %w", err)
	}

	buf := make([]byte, unix.Getpagesize())
	var tab []byte
	for {
		n, _, err := unix.Recvfrom(b.syncSocket, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("failed to read netlink response: %w", err)
		}
		if n < unix.NLMSG_HDRLEN {
			return nil, unix.EINVAL
		}
		chunk := buf[:n]
		tab = append(tab, chunk...)
		msgs, err := syscall.ParseNetlinkMessage(chunk)
		if err != nil {
			return nil, err
		}
		for i := range msgs {
			m := &msgs[i]
			if m.Header.Seq != seq || m.Header.Pid != b.syncPort {
				continue
			}
			if os.IsExist(err) {
				return nil, err
			}
			if err := netlinkErrorFromMessage(m); err != nil {
				err = fmt.Errorf("netlink error: %w", err)
				return nil, err
			}
			switch mode {
			case netlinkWaitAck:
				if m.Header.Type == unix.NLMSG_ERROR {
					return nil, nil
				}
			case netlinkWaitRoute:
				if m.Header.Type == unix.RTM_NEWROUTE {
					return tab, nil
				}
			case netlinkWaitNeigh:
				if m.Header.Type == unix.RTM_NEWNEIGH {
					return tab, nil
				}
			}
		}
	}
}

func parseNetlinkRoutes(tab []byte) ([]netlinkRoute, error) {
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, err
	}
	var routes []netlinkRoute
	for i := range msgs {
		m := &msgs[i]
		switch m.Header.Type {
		case unix.NLMSG_DONE, unix.NLMSG_ERROR:
			continue
		case unix.RTM_NEWROUTE, unix.RTM_DELROUTE, unix.RTM_GETROUTE:
			if len(m.Data) < unix.SizeofRtMsg {
				continue
			}
			rm := (*syscall.RtMsg)(unsafe.Pointer(&m.Data[0]))
			attrs, err := syscall.ParseNetlinkRouteAttr(m)
			if err != nil {
				continue
			}
			attrMap := make(map[int][]byte, len(attrs))
			for _, a := range attrs {
				attrMap[int(a.Attr.Type)] = a.Value
			}
			routes = append(routes, netlinkRoute{hdr: m.Header, msg: *rm, attrs: attrMap})
		}
	}
	return routes, nil
}

func netlinkErrorFromMessage(m *syscall.NetlinkMessage) error {
	if m.Header.Type != unix.NLMSG_ERROR {
		return nil
	}
	if len(m.Data) < 4 {
		return fmt.Errorf("short netlink error message")
	}
	errno := *(*int32)(unsafe.Pointer(&m.Data[0]))
	if errno != 0 {
		return unix.Errno(-errno)
	}
	return nil
}

type rtAttrEntry struct {
	typ  int
	data []byte
}

func encodeNetlinkNeigh(nlType uint16, flags uint16, seq, port uint32, ndmsg unix.NdMsg, attrs []rtAttrEntry) ([]byte, error) {
	bodyLen := unix.SizeofNdMsg
	for _, a := range attrs {
		bodyLen += rtaLength(len(a.data))
	}
	totalLen := unix.NLMSG_HDRLEN + bodyLen
	buf := make([]byte, totalLen)
	newNlMsghdr(buf, uint32(totalLen), nlType, flags, seq, port)
	copy(buf[unix.NLMSG_HDRLEN:], (*[unix.SizeofNdMsg]byte)(unsafe.Pointer(&ndmsg))[:])
	offset := unix.NLMSG_HDRLEN + unix.SizeofNdMsg
	for _, a := range attrs {
		offset = putRtAttr(buf, offset, a.typ, a.data)
	}
	return buf, nil
}

func parseNetlinkNeighAttrs(tab []byte) (map[int][]byte, bool) {
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, false
	}
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type != unix.RTM_NEWNEIGH {
			continue
		}
		if len(m.Data) < unix.SizeofNdMsg {
			continue
		}
		attrMap := parseRtAttrs(m.Data[unix.SizeofNdMsg:])
		if attrMap == nil {
			continue
		}
		return attrMap, true
	}
	return nil, false
}

func parseRtAttrs(b []byte) map[int][]byte {
	attrMap := make(map[int][]byte)
	for len(b) >= unix.SizeofRtAttr {
		a := (*unix.RtAttr)(unsafe.Pointer(&b[0]))
		if int(a.Len) < unix.SizeofRtAttr || int(a.Len) > len(b) {
			return nil
		}
		valLen := int(a.Len) - unix.SizeofRtAttr
		attrMap[int(a.Type)] = b[unix.SizeofRtAttr : unix.SizeofRtAttr+valLen]
		b = b[rtaAlign(int(a.Len)):]
	}
	return attrMap
}

func encodeNetlinkRoute(nlType uint16, flags uint16, seq, port uint32, rtmsg unix.RtMsg, attrs []rtAttrEntry) ([]byte, error) {
	bodyLen := unix.SizeofRtMsg
	for _, a := range attrs {
		bodyLen += rtaLength(len(a.data))
	}
	totalLen := unix.NLMSG_HDRLEN + bodyLen
	buf := make([]byte, totalLen)
	newNlMsghdr(buf, uint32(totalLen), nlType, flags, seq, port)
	copy(buf[unix.NLMSG_HDRLEN:], (*[unix.SizeofRtMsg]byte)(unsafe.Pointer(&rtmsg))[:])
	offset := unix.NLMSG_HDRLEN + unix.SizeofRtMsg
	for _, a := range attrs {
		offset = putRtAttr(buf, offset, a.typ, a.data)
	}
	return buf, nil
}

func newNlMsghdr(buf []byte, length uint32, nlType, flags uint16, seq, pid uint32) {
	binary.NativeEndian.PutUint32(buf[0:4], length)
	binary.NativeEndian.PutUint16(buf[4:6], nlType)
	binary.NativeEndian.PutUint16(buf[6:8], flags)
	binary.NativeEndian.PutUint32(buf[8:12], seq)
	binary.NativeEndian.PutUint32(buf[12:16], pid)
}

func putRtAttr(buf []byte, offset, typ int, data []byte) int {
	attrLen := unix.SizeofRtAttr + len(data)
	aligned := rtaLength(len(data))
	attr := (*unix.RtAttr)(unsafe.Pointer(&buf[offset]))
	attr.Len = uint16(attrLen)
	attr.Type = uint16(typ)
	copy(buf[offset+unix.SizeofRtAttr:], data)
	return offset + aligned
}

func rtaLength(dataLen int) int {
	return rtaAlign(unix.SizeofRtAttr + dataLen)
}

func rtaAlign(n int) int {
	return (n + unix.RTA_ALIGNTO - 1) & ^(unix.RTA_ALIGNTO - 1)
}

func includeLoadedRoute(rm *syscall.RtMsg) bool {
	if isLinkScopeNeighbor(rm) {
		return true
	}
	switch rm.Type {
	case unix.RTN_LOCAL, unix.RTN_BROADCAST, unix.RTN_MULTICAST, unix.RTN_BLACKHOLE,
		unix.RTN_UNREACHABLE, unix.RTN_PROHIBIT, unix.RTN_THROW:
		return false
	}
	if rm.Scope == unix.RT_SCOPE_HOST {
		return false
	}
	return true
}

func isLinkScopeNeighbor(rm *syscall.RtMsg) bool {
	return rm.Scope == unix.RT_SCOPE_LINK && rm.Type == unix.RTN_UNICAST
}

func attrUint32(b []byte) uint32 {
	if len(b) < 4 {
		return 0
	}
	return binary.NativeEndian.Uint32(b)
}

func routeFromNeighbor(target net.IP) (*Route, error) {
	return nil, errors.New("not implemented")
}
