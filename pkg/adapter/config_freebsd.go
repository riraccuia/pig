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

//go:build freebsd

package adapter

import (
	"fmt"
	"net"
	"os"
	"slices"
	"unsafe"

	"golang.org/x/sys/unix"
)

// FreeBSD ioctl encoding (sys/ioccom.h).
const (
	_IOC_VOID  = 0x20000000
	_IOC_OUT   = 0x40000000
	_IOC_IN    = 0x80000000
	_IOC_INOUT = _IOC_IN | _IOC_OUT
)

// Tun ioctls from sys/net/if_tun.h (not exported by golang.org/x/sys/unix).
const (
	// TUNGIFNAME = _IOR('t', 93, struct ifreq)
	TUNGIFNAME = _IOC_OUT | (32&0x1fff)<<16 | uint(byte('t'))<<8 | 93
	// TUNSIFMODE = _IOW('t', 94, int)
	TUNSIFMODE = _IOC_IN | (4&0x1fff)<<16 | uint(byte('t'))<<8 | 94
	// TUNSIFPID = _IO('t', 95)
	TUNSIFPID = _IOC_VOID | uint(byte('t'))<<8 | 95
	// TUNSIFHEAD = _IOW('t', 96, int)
	TUNSIFHEAD = _IOC_IN | (4&0x1fff)<<16 | uint(byte('t'))<<8 | 96
)

// ND6 / in6 address flags from netinet6/nd6.h and in6_var.h.
const (
	ND6_IFF_AUTO_LINKLOCAL = 0x20
	ND6_IFF_NO_DAD         = 0x100
	ND6_INFINITE_LIFETIME  = 0xffffffff

	IN6_IFF_TEMPORARY = 0x80
)

// Ioctl numbers whose IOC size depends on the local struct layout (LP64).
var (
	// SIOCGIFINFO_IN6 = _IOWR('i', 108, struct in6_ndireq)
	sioCGIFINFO_IN6 = _IOC_INOUT | (uint(unsafe.Sizeof(in6_ndireq{}))&0x1fff)<<16 | uint(byte('i'))<<8 | 108
	// SIOCSIFINFO_IN6 = _IOWR('i', 109, struct in6_ndireq)
	sioCSIFINFO_IN6 = _IOC_INOUT | (uint(unsafe.Sizeof(in6_ndireq{}))&0x1fff)<<16 | uint(byte('i'))<<8 | 109
	// SIOCAIFADDR_IN6 = _IOW('i', 27, struct in6_aliasreq)
	sioCAIFADDR_IN6 = _IOC_IN | (uint(unsafe.Sizeof(in6_aliasreq{}))&0x1fff)<<16 | uint(byte('i'))<<8 | 27
	// SIOCGIFAFLAG_IN6 = _IOWR('i', 73, struct in6_ifreq)
	sioCGIFAFLAG_IN6 = _IOC_INOUT | (uint(unsafe.Sizeof(in6_ifreq{}))&0x1fff)<<16 | uint(byte('i'))<<8 | 73
)

type ifreqName struct {
	Name [unix.IFNAMSIZ]byte
	_    [16]byte
}

type ifreqMTU struct {
	Name [unix.IFNAMSIZ]byte
	MTU  int32
	_    [12]byte
}

type ifreqFlags struct {
	Name  [unix.IFNAMSIZ]byte
	Flags int16
	_     [14]byte
}

type ifaliasreq struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
	Dest unix.RawSockaddrInet4
	Mask unix.RawSockaddrInet4
}

// in6_ndireq matches FreeBSD's struct in6_ndireq (netinet6/nd6.h).
type in6_ndireq struct {
	Name          [unix.IFNAMSIZ]byte
	Linkmtu       uint32
	Maxmtu        uint32
	Basereachable uint32
	Reachable     uint32
	Retrans       uint32
	Flags         uint32
	Recalctm      int32
	Chlim         uint8
	Initialized   uint8
	Randomseed0   [8]byte
	Randomseed1   [8]byte
	Randomid      [8]byte
}

type in6_addrlifetime struct {
	Expire    int64
	Preferred int64
	Vltime    uint32
	Pltime    uint32
}

// in6_aliasreq matches FreeBSD's struct in6_aliasreq on LP64.
type in6_aliasreq struct {
	Name       [unix.IFNAMSIZ]byte
	Addr       unix.RawSockaddrInet6
	Dest       unix.RawSockaddrInet6
	PrefixMask unix.RawSockaddrInet6
	Flags      int32
	Lifetime   in6_addrlifetime
	Vhid       int32
}

type ifAddr struct {
	IP    net.IP
	IpNet *net.IPNet
}

// in6_ifreq matches FreeBSD's struct in6_ifreq: name plus a union whose
// largest member (icmp6_ifstat) is 272 bytes on LP64.
type in6_ifreq struct {
	Name [unix.IFNAMSIZ]byte
	Ifru [272]byte
}

// configureTUN creates and configures a TUN interface on FreeBSD.
// The kernel assigns tunN; IFHEAD mode prepends a 4-byte address-family header.
func configureTUN(config *AdapterConfig) (ifName string, adapter *tunAdapter, err error) {
	tunFile, err := os.OpenFile("/dev/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", nil, fmt.Errorf("failed to open /dev/tun: %w", err)
	}
	fd := int(tunFile.Fd())

	ifName, err = tunName(fd)
	if err != nil {
		tunFile.Close()
		return "", nil, err
	}

	fail := func(op string, e error) (string, *tunAdapter, error) {
		destroyTUN(ifName)
		tunFile.Close()
		return "", nil, fmt.Errorf("%s: %w", op, e)
	}

	if err = unix.IoctlSetPointerInt(fd, TUNSIFHEAD, 1); err != nil {
		return fail("TUNSIFHEAD", err)
	}

	if err = unix.IoctlSetPointerInt(fd, TUNSIFMODE, unix.IFF_BROADCAST|unix.IFF_MULTICAST); err != nil {
		return fail("TUNSIFMODE", err)
	}

	if err = unix.IoctlSetInt(fd, TUNSIFPID, 0); err != nil {
		return fail("TUNSIFPID", err)
	}

	for _, address := range config.Address {
		ip, ipNet, err := net.ParseCIDR(address)
		if err != nil {
			return fail("parse address", fmt.Errorf("invalid CIDR address: %w", err))
		}
		if err = addAdapterAddress(0, ifName, ip, ipNet.Mask); err != nil {
			return fail("set address", err)
		}
	}

	if err = setAdapterMTU(0, ifName, config.MTU); err != nil {
		return fail("set MTU", err)
	}

	if err = bringAdapterUp(ifName); err != nil {
		return fail("bring up", err)
	}

	if err = unix.SetNonblock(fd, true); err != nil {
		return fail("set non-blocking", err)
	}

	return ifName, &tunAdapter{fd: tunFile, name: ifName}, nil
}

func tunName(fd int) (string, error) {
	var ifr ifreqName
	if err := unix.IoctlSetInt(fd, TUNGIFNAME, int(uintptr(unsafe.Pointer(&ifr)))); err != nil {
		return "", fmt.Errorf("TUNGIFNAME: %w", err)
	}
	return unix.ByteSliceToString(ifr.Name[:]), nil
}

func destroyTUN(ifName string) error {
	if ifName == "" {
		return nil
	}
	netfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(netfd)

	var ifr ifreqName
	copy(ifr.Name[:], ifName)
	if err = unix.IoctlSetInt(netfd, unix.SIOCIFDESTROY, int(uintptr(unsafe.Pointer(&ifr)))); err != nil {
		return fmt.Errorf("SIOCIFDESTROY %s: %w", ifName, err)
	}
	return nil
}

func disableAutoLinkLocal(ifName string) error {
	netfd, err := unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("failed to create IPv6 control socket: %w", err)
	}
	defer unix.Close(netfd)

	var ndireq in6_ndireq
	copy(ndireq.Name[:], ifName)
	if err = unix.IoctlSetInt(netfd, sioCGIFINFO_IN6, int(uintptr(unsafe.Pointer(&ndireq)))); err != nil {
		return fmt.Errorf("SIOCGIFINFO_IN6: %w", err)
	}
	ndireq.Flags &^= ND6_IFF_AUTO_LINKLOCAL
	ndireq.Flags |= ND6_IFF_NO_DAD
	if err = unix.IoctlSetInt(netfd, sioCSIFINFO_IN6, int(uintptr(unsafe.Pointer(&ndireq)))); err != nil {
		return fmt.Errorf("SIOCSIFINFO_IN6: %w", err)
	}
	return nil
}

func setAdapterMTU(netfd int, ifName string, mtu int) error {
	var err error
	if netfd == 0 {
		netfd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("failed to create network control socket: %w", err)
		}
		defer unix.Close(netfd)
	}
	if mtu == 0 {
		mtu = 1300
	}
	var ifrm ifreqMTU
	copy(ifrm.Name[:], ifName)
	ifrm.MTU = int32(mtu)
	if err = unix.IoctlSetInt(netfd, unix.SIOCSIFMTU, int(uintptr(unsafe.Pointer(&ifrm)))); err != nil {
		return fmt.Errorf("SIOCSIFMTU: %w", err)
	}
	return nil
}

func bringAdapterUp(ifName string) error {
	netfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("failed to create network control socket: %w", err)
	}
	defer unix.Close(netfd)

	var ifr ifreqFlags
	copy(ifr.Name[:], ifName)
	if err = unix.IoctlSetInt(netfd, unix.SIOCGIFFLAGS, int(uintptr(unsafe.Pointer(&ifr)))); err != nil {
		return fmt.Errorf("SIOCGIFFLAGS: %w", err)
	}
	ifr.Flags |= int16(unix.IFF_UP)
	if err = unix.IoctlSetInt(netfd, unix.SIOCSIFFLAGS, int(uintptr(unsafe.Pointer(&ifr)))); err != nil {
		return fmt.Errorf("SIOCSIFFLAGS: %w", err)
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

func addAdapterAddressV4(netfd int, ifName string, ipAddr net.IP, mask net.IPMask) error {
	var err error
	if ipAddr.To4() == nil {
		return fmt.Errorf("invalid IPv4 address: %s", ipAddr)
	}
	if netfd == 0 {
		netfd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("failed to create network control socket: %w", err)
		}
		defer unix.Close(netfd)
	}

	var ifra ifaliasreq
	copy(ifra.Name[:], ifName)

	ifra.Addr.Len = unix.SizeofSockaddrInet4
	ifra.Addr.Family = unix.AF_INET
	copy(ifra.Addr.Addr[:], ipAddr.To4())

	ifra.Dest.Len = unix.SizeofSockaddrInet4
	ifra.Dest.Family = unix.AF_INET
	copy(ifra.Dest.Addr[:], ipAddr.To4())

	ifra.Mask.Len = unix.SizeofSockaddrInet4
	ifra.Mask.Family = unix.AF_INET
	copy(ifra.Mask.Addr[:], mask)

	if err = unix.IoctlSetInt(netfd, unix.SIOCAIFADDR, int(uintptr(unsafe.Pointer(&ifra)))); err != nil {
		return fmt.Errorf("SIOCAIFADDR: %w", err)
	}
	return nil
}

func addAdapterAddressV6(netfd int, ifName string, ipAddr net.IP, mask net.IPMask) error {
	var err error
	if netfd == 0 {
		netfd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return fmt.Errorf("failed to create network control socket: %w", err)
		}
		defer unix.Close(netfd)
	}

	var ifra6 in6_aliasreq
	copy(ifra6.Name[:], ifName)

	ifra6.Addr.Len = unix.SizeofSockaddrInet6
	ifra6.Addr.Family = unix.AF_INET6
	copy(ifra6.Addr.Addr[:], ipAddr.To16())

	ifra6.PrefixMask.Len = unix.SizeofSockaddrInet6
	ifra6.PrefixMask.Family = unix.AF_INET6
	copy(ifra6.PrefixMask.Addr[:], mask)

	ifra6.Lifetime.Expire = 0
	ifra6.Lifetime.Preferred = 0
	ifra6.Lifetime.Vltime = ND6_INFINITE_LIFETIME
	ifra6.Lifetime.Pltime = ND6_INFINITE_LIFETIME

	if err = unix.IoctlSetInt(netfd, sioCAIFADDR_IN6, int(uintptr(unsafe.Pointer(&ifra6)))); err != nil {
		return fmt.Errorf("SIOCAIFADDR_IN6: %w", err)
	}
	return nil
}

// getAdapterAddress retrieves the best adapter address for the given family.
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
		ipv6Addrs []ifAddr
		ioctlFd   int
		sa        *unix.RawSockaddrInet6
	)
	if family == unix.AF_INET6 {
		ioctlFd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to create network control socket: %w", err)
		}
		defer unix.Close(ioctlFd)
		sa = &unix.RawSockaddrInet6{
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

	type rankedAddr struct {
		addr ifAddr
		rank int
	}
	ranked := make([]rankedAddr, len(ipv6Addrs))
	for i, a := range ipv6Addrs {
		r := rankIPAddr(a.IP)
		copy(sa.Addr[:], a.IP.To16())
		if flags, err := ioctlGetIfaFlagInet6(ioctlFd, ifName, sa); err == nil && flags&IN6_IFF_TEMPORARY != 0 {
			r++
		}
		ranked[i] = rankedAddr{addr: a, rank: r}
	}
	slices.SortStableFunc(ranked, func(a, b rankedAddr) int {
		return b.rank - a.rank
	})
	return ranked[0].addr.IP, ranked[0].addr.IpNet, nil
}

// ioctlGetIfaFlagInet6 returns the IN6_IFF_* flags for sa on ifName.
func ioctlGetIfaFlagInet6(fd int, ifName string, sa *unix.RawSockaddrInet6) (int32, error) {
	var ifr in6_ifreq
	copy(ifr.Name[:], ifName)
	*(*unix.RawSockaddrInet6)(unsafe.Pointer(&ifr.Ifru)) = *sa
	if err := unix.IoctlSetInt(fd, sioCGIFAFLAG_IN6, int(uintptr(unsafe.Pointer(&ifr)))); err != nil {
		return 0, err
	}
	return *(*int32)(unsafe.Pointer(&ifr.Ifru)), nil
}
