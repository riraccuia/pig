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

package adapter

import (
	"fmt"
	"net"
	"os"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
)

const _IOC_OUT = 0x40000000
const _IOC_IN = 0x80000000
const _IOC_INOUT = _IOC_IN | _IOC_OUT

const (
	CTLIOCGINFO           = 0xc0644e03
	CTLTYPE_NODE          = 1
	SYSPROTO_CONTROL      = 2
	UTUN_OPT_IFNAME       = 2
	IN6_IFF_NODAD         = 0x20   /* don't	perform	DAD on this address */
	IN6_IFF_AUTOCONF      = 0x40   /* autoconfigurable address. */
	IN6_IFF_SECURED       = 0x0400 /* cryptographically generated */
	IN6_IFF_TEMPORARY     = 0x0080 /* temporary address */
	ND6_INFINITE_LIFETIME = 0xffffffff
	// #define	SIOCPROTOATTACH_IN6	_IOWR('i', 110, struct in6_aliasreq_64)
	SIOCPROTOATTACH_IN6 = _IOC_INOUT | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 110
	// #define	SIOCLL_START		_IOWR('i', 130, struct in6_aliasreq)
	SIOCLL_START = _IOC_INOUT | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 130
	// #define	SIOCAIFADDR_IN6		_IOW('i', 26, struct in6_aliasreq) = 0x8080691a
	SIOCAIFADDR_IN6 = _IOC_IN | ((128 & 0x1fff) << 16) | uint32(byte('i'))<<8 | 26
)

type ifaliasreq struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
	Dest unix.RawSockaddrInet4
	Mask unix.RawSockaddrInet4
}

// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6_var.h#L114-L119
// https://opensource.apple.com/source/network_cmds/network_cmds-543.260.3/
type in6_addrlifetime struct {
	ia6t_expire    uint64
	ia6t_preferred uint64
	ia6t_vltime    uint32
	ia6t_pltime    uint32
}

// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6_var.h#L336-L343
// https://github.com/apple/darwin-xnu/blob/a449c6a3b8014d9406c2ddbdc81795da24aa7443/bsd/netinet6/in6.h#L174-L181
type in6_aliasreq struct {
	Name       [unix.IFNAMSIZ]byte
	Addr       unix.RawSockaddrInet6
	Dest       unix.RawSockaddrInet6
	PrefixMask unix.RawSockaddrInet6
	Flags      int32
	Lifetime   in6_addrlifetime
}

// configureTUN creates and configures a TUN interface on macOS using the utun driver.
// It sets up the interface with the specified name, IP address, MTU, and brings it up.
//
// Parameters:
//   - config: AdapterConfig containing IP address (CIDR notation) and MTU settings
//
// Returns:
//   - ifName: The name of the created interface
//   - adapter: The adapter object
//   - error: nil if successful, otherwise contains the error description
func configureTUN(config AdapterConfig) (ifName string, adapter *utunAdapter, err error) {
	// Create control socket
	sockfd, err := unix.Socket(unix.AF_SYSTEM, unix.SOCK_DGRAM, SYSPROTO_CONTROL)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create control socket: %w", err)
	}
	// defer unix.Close(sockfd)

	// Setup control info structure
	ctlInfo := unix.CtlInfo{}
	copy(ctlInfo.Name[:], []byte("com.apple.net.utun_control"))

	// Get control ID using ioctl
	if err = unix.IoctlCtlInfo(sockfd, &ctlInfo); err != nil {
		return "", nil, fmt.Errorf("failed to get control ID: %w", err)
	}

	// Setup connection request
	sc := &unix.SockaddrCtl{
		ID:   ctlInfo.Id,
		Unit: 0, // System will allocate the next available unit number
	}

	// Connect to the control socket
	if err = unix.Connect(sockfd, sc); err != nil {
		return "", nil, fmt.Errorf("failed to connect control socket: %w", err)
	}

	// Get interface name from kernel, this is the name of the interface that will be created
	ifName, err = unix.GetsockoptString(sockfd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME)
	if err != nil {
		return "", nil, fmt.Errorf("failed to get interface name: %w", err)
	}

	err = unix.SetNonblock(sockfd, true)
	if err != nil {
		return "", nil, fmt.Errorf("failed to set non-blocking mode: %w", err)
	}

	// Create network control socket, set FD_CLOEXEC to avoid leaking file descriptors
	/*netfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.FD_CLOEXEC, unix.IPPROTO_IP)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create network control socket: %w", err)
	}
	defer unix.Close(netfd)*/

	// generate ipv6 link-local address
	// needed since even when the sysctl net.inet6.ip6.auto_linklocal flag is set to 1, it has
	// no effect on tun adapters
	addAdapterAddressV6(0, ifName, nil, nil)

	for _, address := range config.Address {
		ip, ipNet, err := net.ParseCIDR(address)
		if err != nil {
			return "", nil, fmt.Errorf("invalid CIDR address: %w", err)
		}
		if err = addAdapterAddress(0, ifName, ip, ipNet.Mask); err != nil {
			return "", nil, fmt.Errorf("failed to set interface address: %w", err)
		}
	}

	if err = setAdapterMTU(0, ifName, config.MTU); err != nil {
		return "", nil, fmt.Errorf("failed to set interface MTU: %w", err)
	}

	adapter = &utunAdapter{
		fd: os.NewFile(uintptr(sockfd), ""),
	}

	return ifName, adapter, nil
}

func setAdapterMTU(netfd int, ifName string, mtu int) error {
	var err error

	if netfd == 0 {
		// Create network control socket, set FD_CLOEXEC to avoid leaking file descriptors
		netfd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.FD_CLOEXEC, unix.IPPROTO_IP)
		if err != nil {
			return fmt.Errorf("failed to create network control socket: %w", err)
		}
		defer unix.Close(netfd)
	}

	if mtu == 0 {
		mtu = 1300
	}

	mtuRequest := unix.IfreqMTU{}
	copy(mtuRequest.Name[:], ifName)
	mtuRequest.MTU = int32(mtu)

	if err = unix.IoctlSetIfreqMTU(netfd, &mtuRequest); err != nil {
		return fmt.Errorf("SIOCSIFMTU: %w", err)
	}

	return nil
}

func addAdapterAddress(netfd int, ifName string, ip net.IP, mask net.IPMask) error {
	if ip.To4() != nil {
		return addAdapterAddressV4(netfd, ifName, ip, mask)
	}
	if ip.To16() != nil {
		return addAdapterAddressV6(netfd, ifName, ip, mask)
	}
	return fmt.Errorf("invalid IP address: %s", ip)
}

func addAdapterAddressV6(netfd int, ifName string, ipAddr net.IP, mask net.IPMask) error {
	var err error

	if netfd == 0 {
		netfd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.FD_CLOEXEC, unix.IPPROTO_IP)
		if err != nil {
			return fmt.Errorf("failed to create network control socket: %w", err)
		}
		defer unix.Close(netfd)
	}

	// Configure IPv6 address
	var ifra6 in6_aliasreq
	copy(ifra6.Name[:], ifName)

	/* Attach link-local address configuration */

	// Attach protocol to IPv6 interface
	if err = unix.IoctlSetInt(netfd, uint(SIOCPROTOATTACH_IN6), int(uintptr(unsafe.Pointer(&ifra6)))); err != nil {
		return fmt.Errorf("SIOCPROTOATTACH_IN6: %w", err)
	}

	// Start link-local address configuration
	if err = unix.IoctlSetInt(netfd, uint(SIOCLL_START), int(uintptr(unsafe.Pointer(&ifra6)))); err != nil {
		return fmt.Errorf("SIOCLL_START: %w", err)
	}

	/* End of link-local address configuration */

	if ipAddr == nil {
		return nil
	}

	if ipAddr.To16() == nil {
		return fmt.Errorf("invalid IPv6 address: %s", ipAddr)
	}

	/* Configure IPv6 address */

	ifra6.Addr.Family = unix.AF_INET6
	ifra6.Addr.Len = unix.SizeofSockaddrInet6
	copy(ifra6.Addr.Addr[:], ipAddr.To16())

	ifra6.PrefixMask.Family = unix.AF_INET6
	ifra6.PrefixMask.Len = unix.SizeofSockaddrInet6
	copy(ifra6.PrefixMask.Addr[:], mask)

	ifra6.Lifetime.ia6t_expire = ND6_INFINITE_LIFETIME
	ifra6.Lifetime.ia6t_preferred = ND6_INFINITE_LIFETIME
	ifra6.Lifetime.ia6t_vltime = ND6_INFINITE_LIFETIME
	ifra6.Lifetime.ia6t_pltime = ND6_INFINITE_LIFETIME

	ifra6.Flags = IN6_IFF_SECURED

	if err = unix.IoctlSetInt(netfd, uint(SIOCAIFADDR_IN6), int(uintptr(unsafe.Pointer(&ifra6)))); err != nil {
		return fmt.Errorf("SIOCAIFADDR_IN6: %w", err)
	}

	return nil
}

func addAdapterAddressV4(netfd int, ifName string, ipAddr net.IP, mask net.IPMask) error {
	var err error

	if ipAddr.To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ipAddr)
	}

	if netfd == 0 {
		// Create network control socket, set FD_CLOEXEC to avoid leaking file descriptors
		netfd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.FD_CLOEXEC, unix.IPPROTO_IP)
		if err != nil {
			return fmt.Errorf("failed to create network control socket: %w", err)
		}
		defer unix.Close(netfd)
	}

	// Prepare interface alias request
	var ifra ifaliasreq
	copy(ifra.Name[:], ifName)

	// Setup IP address
	ifra.Addr.Family = unix.AF_INET
	ifra.Addr.Len = unix.SizeofSockaddrInet4
	copy(ifra.Addr.Addr[:], ipAddr.To4())

	// Setup destination IP address
	ifra.Dest.Family = unix.AF_INET
	ifra.Dest.Len = unix.SizeofSockaddrInet4
	copy(ifra.Dest.Addr[:], ipAddr.To4())

	// Setup netmask
	ifra.Mask.Family = unix.AF_INET
	ifra.Mask.Len = unix.SizeofSockaddrInet4
	copy(ifra.Mask.Addr[:], mask)

	// Configure IP using SIOCAIFADDR, this is the socket option that sets the IP address
	if err = unix.IoctlSetInt(netfd, unix.SIOCAIFADDR, int(uintptr(unsafe.Pointer(&ifra)))); err != nil {
		return fmt.Errorf("SIOCAIFADDR: %w", err)
	}

	return nil
}

type ifAddr struct {
	IP    net.IP
	IpNet *net.IPNet
}

// getAdapterAddress retrieves the best adapter address for the given family, to be used
// immediately in order to establish an outbound connection.
func getAdapterAddress(ifName string, family int) (net.IP, *net.IPNet, error) {
	itf, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get interface: %w", err)
	}
	ipAddrs, err := itf.Addrs()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get interface addresses: %w", err)
	}
	var (
		ipv6Addrs        []ifAddr
		ioctlFd          int
		rawSockaddrInet6 *unix.RawSockaddrInet6
	)
	if family == unix.AF_INET6 {
		ioctlFd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_IP)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create network control socket: %w", err)
		}
		defer unix.Close(ioctlFd)
		rawSockaddrInet6 = &unix.RawSockaddrInet6{
			Family: unix.AF_INET6,
			Len:    unix.SizeofSockaddrInet6,
		}
	}
	for _, addr := range ipAddrs {
		ip, ipNet, err := net.ParseCIDR(addr.String())
		if err != nil {
			continue
		}
		if family == unix.AF_INET {
			if ip.To4() != nil {
				return ip, ipNet, nil
			}
			continue
		}
		if ip.To4() != nil {
			continue
		}
		if ip.To16() != nil {
			ipv6Addrs = append(ipv6Addrs, ifAddr{IP: ip, IpNet: ipNet})
		}
	}
	if family == unix.AF_INET || len(ipv6Addrs) == 0 {
		return nil, nil, fmt.Errorf("no address found for interface: %s", ifName)
	}
	rank := func(addr ifAddr) int {
		r := rankIPAddr(addr.IP)
		copy(rawSockaddrInet6.Addr[:], addr.IP.To16())
		flagsA, err := IoctlGetIfaFlagInet6(ioctlFd, ifName, rawSockaddrInet6)
		if err != nil {
			return r
		}
		if flagsA&IN6_IFF_TEMPORARY != 0 {
			r++
		}
		return r
	}
	slices.SortStableFunc(ipv6Addrs, func(a, b ifAddr) int {
		return rank(b) - rank(a)
	})
	return ipv6Addrs[0].IP, ipv6Addrs[0].IpNet, nil
}

type inet6Ifreq struct {
	Name [unix.IFNAMSIZ]byte
	Ifru [272]byte
}

// IoctlGetIfaFlagInet6 retrieves the interface IPv6 address flags for sa.
// fd is expected to be a network control socket for ipv6.
func IoctlGetIfaFlagInet6(fd int, ifName string, sa *unix.RawSockaddrInet6) (flags int32, err error) {
	const SIOCGIFAFLAG_IN6 = 0xc1206949
	var ifr inet6Ifreq
	_ = copy(ifr.Name[:], ifName)
	*(*unix.RawSockaddrInet6)(unsafe.Pointer(&ifr.Ifru)) = *sa
	if err := ioctlPtr(fd, SIOCGIFAFLAG_IN6, unsafe.Pointer(&ifr)); err != nil {
		return 0, os.NewSyscallError("ioctl", err)
	}
	return *(*int32)(unsafe.Pointer(&ifr.Ifru)), nil
}

//go:linkname ioctlPtr golang.org/x/sys/unix.ioctlPtr
//go:noescape
func ioctlPtr(fd int, req uint, arg unsafe.Pointer) (err error)
