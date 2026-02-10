//go:build darwin

package route

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

type darwinManager struct {
	defGwCond       *sync.Cond
	socketV4        int // file descriptor for the IPv4 route socket
	socketV6        int // file descriptor for the IPv6 route socket
	ctx             context.Context
	cancel          context.CancelFunc
	trackedRoutesV4 sync.Map     // map[string]Route - key is route string representation
	trackedRoutesV6 sync.Map     // map[string]Route - key is route string representation
	defaultGateway4 atomic.Value // net.IP - IPv4 default gateway (nil if not set)
	defaultGateway6 atomic.Value // net.IP - IPv6 default gateway (nil if not set)
}

func openRouteSocket(family int) (int, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, family)
	if err != nil {
		return 0, fmt.Errorf("failed to create route socket: %w", err)
	}
	return fd, nil
}

func newManager(ctx context.Context) (manager, error) {
	fdV4, err := openRouteSocket(unix.AF_INET)
	if err != nil {
		return nil, err
	}

	fdV6, err := openRouteSocket(unix.AF_INET6)
	if err != nil {
		unix.Close(fdV4)
		return nil, err
	}

	var (
		mCtx   = context.Background()
		cancel context.CancelFunc
	)

	if ctx != nil {
		mCtx = ctx
	}

	mCtx, cancel = context.WithCancel(mCtx)

	manager := &darwinManager{
		socketV4:  fdV4,
		socketV6:  fdV6,
		ctx:       mCtx,
		cancel:    cancel,
		defGwCond: sync.NewCond(&sync.Mutex{}),
	}

	// Perform reconnaissance to discover default gateways
	manager.discoverDefaultGateways()

	// Start route monitoring routine
	go manager.monitorRoutesV4()
	go manager.monitorRoutesV6()

	runtime.Gosched()

	return manager, nil
}

func (m *darwinManager) routeSocketForRoute(rt *Route) (int, error) {
	if rt.Is4() {
		if m.socketV4 == 0 {
			return 0, fmt.Errorf("IPv4 route socket is closed")
		}
		return m.socketV4, nil
	}
	if m.socketV6 == 0 {
		return 0, fmt.Errorf("IPv6 route socket is closed")
	}
	return m.socketV6, nil
}

// trackedRoutesForRoute selects the tracking map by IP family.
func (m *darwinManager) trackedRoutesForRoute(rt *Route) *sync.Map {
	if rt.Is4() {
		return &m.trackedRoutesV4
	}
	return &m.trackedRoutesV6
}

func (m *darwinManager) AddRoute(rt *Route) error {
	// Build route message
	msg, err := m.buildRouteMessageWithBestRoute(rt, unix.RTM_ADD, 0)
	if err != nil {
		return fmt.Errorf("failed to build route message: %w", err)
	}

	socket, err := m.routeSocketForRoute(rt)
	if err != nil {
		return err
	}

	// Send message using persistent socket
	_, err = unix.Write(socket, msg)
	if err != nil {
		return fmt.Errorf("failed to send route message: %w", err)
	}

	// Track the route for cleanup using route string representation
	trackedRoutes := m.trackedRoutesForRoute(rt)
	trackedRoutes.Store(rt.String(), rt)
	return nil
}

func (m *darwinManager) RemoveRoute(rt *Route) error {
	// Build route message
	msg, err := m.buildRouteMessageRaw(rt, unix.RTM_DELETE, 0)
	if err != nil {
		return fmt.Errorf("failed to build route message: %w", err)
	}

	socket, err := m.routeSocketForRoute(rt)
	if err != nil {
		return err
	}

	// Send message using persistent socket
	_, err = unix.Write(socket, msg)
	if err != nil {
		return fmt.Errorf("failed to send route message: %w", err)
	}

	// Remove from tracking
	trackedRoutes := m.trackedRoutesForRoute(rt)
	trackedRoutes.Delete(rt.String())
	return nil
}

func (m *darwinManager) Cleanup() error {
	var err error
	// cleanup tracked routes v4
	e := m.cleanup(&m.trackedRoutesV4)
	if e != nil {
		// wrap error
		err = wrapError(err, e, "failed to cleanup tracked routes v4")
	}
	// cleanup tracked routes v6
	e = m.cleanup(&m.trackedRoutesV6)
	if e != nil {
		// wrap error, combine with previous error
		err = wrapError(err, e, "failed to cleanup tracked routes v6")
	}
	return err
}

func (m *darwinManager) cleanup(trackedRoutes *sync.Map) error {
	// Collect all routes to remove
	var routesToRemove []*Route
	trackedRoutes.Range(func(key, value interface{}) bool {
		if rt, ok := value.(*Route); ok {
			routesToRemove = append(routesToRemove, rt)
		}
		return true
	})

	var errReturn error
	// Remove all tracked routes
	for _, rt := range routesToRemove {
		err := m.RemoveRoute(rt)
		if err != nil {
			errReturn = wrapError(errReturn, err, fmt.Sprintf("failed to cleanup route %s", rt.String()))
		}
	}

	return errReturn
}

func (m *darwinManager) WaitDefaultGateway(v4, v6 bool) <-chan struct{} {
	ch := make(chan struct{})
	go func() {
		m.waitDefaultGateway(v4, v6)
		close(ch)
	}()
	return ch
}

func (m *darwinManager) waitDefaultGateway(v4, v6 bool) {
	m.defGwCond.L.Lock()
	for {
		if v4 && m.GetDefaultGateway4() == nil {
			m.defGwCond.Wait()
			continue
		}
		if v6 && m.GetDefaultGateway6() == nil {
			m.defGwCond.Wait()
			continue
		}
		break
	}
	m.defGwCond.L.Unlock()
}

func (m *darwinManager) GetRoutes() ([]*Route, error) {
	msgs, err := m.getRouteMessages()
	if err != nil {
		return nil, err
	}

	var routes []*Route
	m.processRouteMessages(msgs, func(rt *Route, rm *route.RouteMessage) {
		routes = append(routes, rt)
	})

	return routes, nil
}

// getRouteMessages fetches and parses route messages from the system
func (m *darwinManager) getRouteMessages() ([]route.Message, error) {
	// Read the routing table using the route package's FetchRIB function
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

// processRouteMessages iterates through route messages and calls the provided function for each valid route
func (m *darwinManager) processRouteMessages(msgs []route.Message, fn func(*Route, *route.RouteMessage)) {
	for _, msg := range msgs {
		rm, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}

		rt, err := m.convertRouteMessage(rm)
		if err != nil {
			continue // Skip routes we can't parse
		}

		fn(rt, rm)
	}
}

// convertRouteMessage converts a route.RouteMessage to our Route struct
func (m *darwinManager) convertRouteMessage(rm *route.RouteMessage) (*Route, error) {
	var (
		rt            = &Route{}
		destination   net.IP
		gateway       net.IP
		netmask       net.IPMask
		interfaceName string
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
			// no ARP for now, but we will use it later
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

	return rt, nil
}

func (m *darwinManager) Close() error {
	// Cancel the monitoring routine
	if m.cancel != nil {
		m.cancel()
	}

	if m.socketV4 != 0 {
		err := unix.Close(m.socketV4)
		m.socketV4 = 0
		if err != nil {
			return err
		}
	}

	if m.socketV6 != 0 {
		err := unix.Close(m.socketV6)
		m.socketV6 = 0
		return err
	}
	return nil
}

func (m *darwinManager) monitorRoutesV4() {
	m.monitorRoutes(m.socketV4, unix.AF_INET)
}

func (m *darwinManager) monitorRoutesV6() {
	m.monitorRoutes(m.socketV6, unix.AF_INET6)
}

func (m *darwinManager) monitorRoutes(socket, family int) {
	buf := make([]byte, 4096)

	err := unix.SetNonblock(socket, true)
	if err != nil {
		return
	}

	for {
		select {
		case <-m.ctx.Done():
			return
		default:
			n, err := unix.Read(socket, buf)
			if err != nil {
				// Check if it's a "would block" error (no data available)
				if err == unix.EAGAIN || err == unix.EWOULDBLOCK {
					continue
				}
				// Other errors - socket might be closed
				return
			}

			if n > 0 {
				m.handleRouteMessage(buf[:n], family)
			}
		}
	}
}

func (m *darwinManager) handleRouteMessage(msg []byte, family int) {
	// Parse using golang.org/x/net/route
	msgs, err := route.ParseRIB(route.RIBTypeRoute, msg)
	if err != nil {
		return
	}

	for _, msg := range msgs {
		switch rm := msg.(type) {
		case *route.RouteMessage:
			rt, err := m.convertRouteMessage(rm)
			if err != nil {
				continue
			}

			rtFamily := unix.AF_INET
			if !rt.Is4() {
				rtFamily = unix.AF_INET6
			}

			if rtFamily != family {
				continue
			}

			if family == unix.AF_INET {
				m.updateDefaultGatewayIfNeeded(rt, rm)
				continue
			}

			// from here it's IPv6

			if rm.Type != unix.RTM_ADD {
				continue
			}

			if rm.Flags&unix.RTF_IFSCOPE != 0 && rm.Flags&unix.RTF_LOCAL != 0 && rm.Flags&unix.RTF_LLINFO != 0 {
				go func() {
					time.Sleep(5 * time.Second)
					ip, routeMsg, err := m.discoverIfDefaultGateway6(rm.Index)
					if err != nil {
						return
					}
					dr := &Route{
						Destination: &net.IPNet{
							IP:   net.IPv6zero,
							Mask: net.CIDRMask(0, 128),
						},
						Gateway: ip,
					}
					m.updateDefaultGatewayIfNeeded(dr, routeMsg)
				}()
			}
		}
	}
}

// createInet4Addr creates a route.Inet4Addr from a net.IP
func (m *darwinManager) createInetAddr(ip net.IP) route.Addr {
	if ip.To4() != nil {
		var ip4 [4]byte
		copy(ip4[:], ip.To4())
		return &route.Inet4Addr{IP: ip4}
	}
	var ip6 [16]byte
	copy(ip6[:], ip.To16())
	return &route.Inet6Addr{IP: ip6}
}

// calculateNetworkAddress calculates the network address from IP and mask
func (m *darwinManager) calculateNetworkAddress(ipnet *net.IPNet) net.IP {
	ones, bits := ipnet.Mask.Size()
	if ones == bits {
		// Host route - return the IP as-is
		return ipnet.IP
	}
	// Network route - calculate network address
	return ipnet.IP.Mask(ipnet.Mask)
}

// buildRouteMessageRaw builds a route message with whatever is provided in the route struct
// the only mandatory field is the destination
func (m *darwinManager) buildRouteMessageRaw(rt *Route, msgType int, flags int) ([]byte, error) {
	var (
		addrs []route.Addr
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

	// Calculate the correct destination address (network vs host)
	destinationIP := m.calculateNetworkAddress(rt.Destination)
	if destinationIP == nil {
		return nil, fmt.Errorf("invalid route destination: %v", rt.Destination.String())
	}

	// Add destination address in position 0
	addrs = append(addrs, m.createInetAddr(destinationIP))

	if rt.Gateway != nil {
		addrs = append(addrs, m.createInetAddr(rt.Gateway))
	}

	if rt.Interface != "" {
		iface, err := net.InterfaceByName(rt.Interface)
		if err != nil {
			return nil, fmt.Errorf("interface %s not found: %w", rt.Interface, err)
		}
		msg.Index = iface.Index
	}

	// Add netmask address in position 2
	ones, bits := rt.Destination.Mask.Size()
	if ones != bits {
		maskIP := net.IP(rt.Destination.Mask)
		// Add netmask address in position 2
		addrs = append(addrs, m.createInetAddr(maskIP))
	}

	// Create RouteMessage
	msg.Flags |= flags | unix.RTF_UP | unix.RTF_STATIC | unix.RTF_PRCLONING

	msg.Addrs = addrs

	return msg.Marshal()
}

func (m *darwinManager) buildRouteMessageWithBestRoute(rt *Route, msgType int, flags int) ([]byte, error) {
	// If the gateway is nil, use the default gateway for the destination IP version
	if rt.Gateway == nil {
		bestRoute, err := m.FindBestRoute(rt.Destination.IP)
		if err != nil {
			return nil, err
		}
		rt.Gateway = bestRoute.Gateway
		rt.Interface = bestRoute.Interface
	}

	// Gateway
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

	// Create RouteMessage
	return m.buildRouteMessageRaw(rt, msgType, flags)
}

// updateDefaultGateway updates the default gateway for a given IP version
func (m *darwinManager) updateDefaultGateway(rt *Route, rm *route.RouteMessage, defaultGatewayVal *atomic.Value) {
	switch rm.Type {
	case unix.RTM_GET, unix.RTM_ADD, unix.RTM_CHANGE:
		// Only update if we don't already have a default gateway stored
		// This ensures we keep the first/default route
		//if val := defaultGatewayVal.Load(); val == nil {
		if isValidGateway(rt.Gateway, rm.Flags) {
			defaultGatewayVal.Store(rt.Gateway)
			m.defGwCond.Broadcast()
		}
		//}
	case unix.RTM_DELETE:
		// Check if the deleted route matches current default gateway
		if val := defaultGatewayVal.Load(); val != nil {
			if storedGateway := val.(net.IP); storedGateway != nil && rt.Gateway != nil && storedGateway.Equal(rt.Gateway) {
				defaultGatewayVal.Store(net.IP(nil))
				// Re-discover to find new default gateway if one exists
				m.discoverDefaultGateways()
			}
		}
	}
}

// updateDefaultGatewayIfNeeded checks if a route change affects default gateways and updates atomically
func (m *darwinManager) updateDefaultGatewayIfNeeded(rt *Route, rm *route.RouteMessage) {
	if rt.Destination == nil {
		return
	}

	ones, bits := rt.Destination.Mask.Size()
	if ones != 0 {
		return // Not a default route
	}

	// Handle IPv4 default route
	if bits == 32 {
		m.updateDefaultGateway(rt, rm, &m.defaultGateway4)
		return
	}

	// Handle IPv6 default route
	if bits == 128 {
		m.updateDefaultGateway(rt, rm, &m.defaultGateway6)
	}
}

// GetDefaultGateway4 returns the IPv4 default gateway (nil if not set)
func (m *darwinManager) GetDefaultGateway4() net.IP {
	return m.getDefaultGateway(&m.defaultGateway4)
}

// GetDefaultGateway6 returns the IPv6 default gateway (nil if not set)
func (m *darwinManager) GetDefaultGateway6() net.IP {
	return m.getDefaultGateway(&m.defaultGateway6)
}

func (m *darwinManager) FindBestRoute(dst net.IP) (*Route, error) {
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
	}
	msg.Addrs = []route.Addr{m.createInetAddr(dst)}

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
		rt, err := m.convertRouteMessage(rm)
		if err != nil {
			return nil, err
		}
		return rt, nil
	}

	return nil, fmt.Errorf("no route response for %s", dst.String())
}

// getDefaultGateway returns the default gateway from the given atomic.Value
func (m *darwinManager) getDefaultGateway(gatewayVal *atomic.Value) net.IP {
	val := gatewayVal.Load()
	if val == nil {
		return nil
	}
	return val.(net.IP)
}

// discoverDefaultGateways performs reconnaissance to find IPv4 and IPv6 default gateways
func (m *darwinManager) discoverDefaultGateways() error {
	var errReturn error

	ip4, routeMsg4, err := m.discoverIfDefaultGateway4(0)
	if err != nil {
		errReturn = err
	}
	if ip4 != nil && routeMsg4 != nil {
		rt4 := &Route{
			Destination: &net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, 32),
			},
			Gateway: ip4,
		}
		// convert interface index to interface name
		iface, err := net.InterfaceByIndex(routeMsg4.Index)
		if err != nil {
			return err
		}
		rt4.Interface = iface.Name
		m.updateDefaultGatewayIfNeeded(rt4, routeMsg4)
	}

	ip6, routeMsg6, err := m.discoverIfDefaultGateway6(0)
	if err != nil && errReturn == nil {
		errReturn = err
	}
	if ip6 != nil && routeMsg6 != nil {
		rt6 := &Route{
			Destination: &net.IPNet{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(0, 128),
			},
			Gateway: ip6,
		}
		// convert interface index to interface name
		iface, err := net.InterfaceByIndex(routeMsg6.Index)
		if err != nil {
			return err
		}
		rt6.Interface = iface.Name
		m.updateDefaultGatewayIfNeeded(rt6, routeMsg6)
	}

	return errReturn
}

func (m *darwinManager) discoverIfDefaultGateway6(ifIndex int) (net.IP, *route.RouteMessage, error) {
	// Fetch routing table to get neighbor discovery entries
	// NDP entries appear as IPv6 routes with LinkAddr (MAC addresses)
	rib, err := route.FetchRIB(unix.AF_INET6, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to fetch IPv6 routing table: %v", err)
	}

	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse route messages: %v", err)
	}

	// Find the router (default gateway) for this interface: next-hop of ::/0 route
	var (
		routerIP net.IP
		routeMsg *route.RouteMessage
	)
	for _, msg := range msgs {
		rm, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}
		if ifIndex > 0 && rm.Index != ifIndex {
			continue
		}
		var dst, gw net.IP
		for i, addr := range rm.Addrs {
			if addr == nil {
				continue
			}
			a, ok := addr.(*route.Inet6Addr)
			if !ok {
				continue
			}
			ip := net.IP(a.IP[:]).To16()
			if i == 0 {
				dst = ip
			}
			if i == 1 {
				gw = ip
			}
		}
		// Default route: destination is ::/0 (all zeros)
		if dst != nil && dst.Equal(net.IPv6zero) && gw != nil {
			routerIP = gw
			routeMsg = rm
			break
		}
	}
	return routerIP, routeMsg, nil
}

func (m *darwinManager) discoverIfDefaultGateway4(ifIndex int) (net.IP, *route.RouteMessage, error) {
	rib, err := route.FetchRIB(unix.AF_INET, route.RIBTypeRoute, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to fetch IPv4 routing table: %v", err)
	}

	msgs, err := route.ParseRIB(route.RIBTypeRoute, rib)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed to parse route messages: %v", err)
	}

	var (
		routerIP net.IP
		routeMsg *route.RouteMessage
	)

	for _, msg := range msgs {
		rm, ok := msg.(*route.RouteMessage)
		if !ok {
			continue
		}
		if ifIndex > 0 && rm.Index != ifIndex {
			continue
		}
		var dst, gw net.IP
		for i, addr := range rm.Addrs {
			if addr == nil {
				continue
			}
			a, ok := addr.(*route.Inet4Addr)
			if !ok {
				continue
			}
			ip := net.IP(a.IP[:]).To4()
			if i == 0 {
				dst = ip
			}
			if i == 1 {
				gw = ip
			}
		}
		if dst != nil && dst.Equal(net.IPv4zero) && gw != nil {
			routerIP = gw
			routeMsg = rm
			break
		}
	}
	return routerIP, routeMsg, nil
}

// isValidGateway checks if an IP address is a valid gateway
func isValidGateway(ip net.IP, routeFlags int) bool {
	if ip == nil {
		return false
	}
	// Check IPv4
	if ip4 := ip.To4(); ip4 != nil {
		// Reject loopback (127.0.0.0/8)
		if ip4[0] == 127 {
			return false
		}
		// Reject link-local (169.254.0.0/16)
		if ip4[0] == 169 && ip4[1] == 254 {
			return false
		}
		return true
	}
	// Check IPv6
	if ip.To16() == nil {
		return false
	}
	ip6 := ip.To16()

	// Reject loopback (::1)
	if ip6.Equal(net.IPv6loopback) {
		return false
	}
	// Check RTF_IFSCOPE flag
	if routeFlags&unix.RTF_IFSCOPE != 0 {
		// e.g. "default fe80::%utun0"
		return false
	}
	return true
	/*
		// Convert IPv6 to big.Int and check link-local prefix (fe80::/10)
		ip6Int := new(big.Int).SetBytes(ip6)
		// Mask for first 10 bits: 0xffc0 << 112, prefix value: 0xfe80 << 112
		mask := new(big.Int).Lsh(new(big.Int).SetUint64(0xffc0), 112)
		prefix := new(big.Int).Lsh(new(big.Int).SetUint64(0xfe80), 112)
		if new(big.Int).And(ip6Int, mask).Cmp(prefix) != 0 {
			// gateway is not link-local layer
			return true
		}
		// Reject fe80:: (all zeros after prefix) - these are interface routes
		if ip6Int.TrailingZeroBits() >= 112 {
			return false
		}
		return true
	*/
}
