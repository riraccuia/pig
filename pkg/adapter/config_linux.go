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
	"io"
	"net"
	"runtime"
	"slices"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	IFF_TUN         = 0x0001
	IFF_TAP         = 0x0002
	IFF_NO_PI       = 0x1000
	IFF_MULTI_QUEUE = 0x0100
	TUNSETIFF       = 0x400454ca
)

type ifreq struct {
	Name  [unix.IFNAMSIZ]byte
	Flags uint16
	pad   [22]byte
}

type ifreqAddr struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
	pad  [8]byte
}

type in6_addr struct {
	addr [16]byte
}

type in6_ifreq struct {
	Addr      in6_addr
	PrefixLen uint32
	Ifindex   int32
}

type ifreqMTU struct {
	Name [unix.IFNAMSIZ]byte
	MTU  int32
	pad  [8]byte
}

// findAvailableTUNName tries to find an available TUN interface name.
func findAvailableTUNName() (string, error) {
	// Try tun0 through tun9
	for i := 0; i < 10; i++ {
		name := fmt.Sprintf("tun%d", i)
		// Check if interface exists
		if _, err := net.InterfaceByName(name); err != nil {
			// Interface doesn't exist, we can use this name
			return name, nil
		}
	}
	return "", fmt.Errorf("no available TUN interface names found")
}

// configureTUN creates and configures a TUN interface on Linux.
// It sets up the interface with the specified name, IP address, MTU, and brings it up.
// Supports multi-queue for better performance: https://www.kernel.org/doc/Documentation/networking/tuntap.txt
func configureTUN(config AdapterConfig) (ifName string, adapter *tunAdapter, err error) {
	// Find available TUN interface name
	ifName, err = findAvailableTUNName()
	if err != nil {
		return "", nil, fmt.Errorf("failed to find available TUN name: %w", err)
	}

	var ifr ifreq
	copy(ifr.Name[:], ifName)
	ifr.Flags = IFF_TUN | IFF_NO_PI

	var numQueues int = 1
	if config.MultiQueue {
		ifr.Flags |= IFF_MULTI_QUEUE
		numQueues = runtime.NumCPU()
	}

	adapter = &tunAdapter{
		devName: ifName,
	}

	for i := 0; i < numQueues; i++ {
		var fd io.ReadWriteCloser
		fd, err = adapter.NewQueue(ifr, len(adapter.queues))
		if err != nil {
			return "", nil, err
		}
		adapter.queues = append(adapter.queues, fd)
	}

	// Get interface name (in case kernel modified it)
	ifName = unix.ByteSliceToString(ifr.Name[:])

	for _, address := range config.Address {
		ip, ipNet, err := net.ParseCIDR(address)
		if err != nil {
			return "", nil, fmt.Errorf("invalid CIDR address: %w", err)
		}
		if err = addAdapterAddress(0, ifName, ip, ipNet.Mask); err != nil {
			return "", nil, fmt.Errorf("failed to set interface address: %w", err)
		}
	}

	var netfd int
	// Create network control socket
	netfd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create network control socket: %w", err)
	}
	defer unix.Close(netfd)

	if err = setAdapterMTU(netfd, ifName, config.MTU); err != nil {
		return "", nil, fmt.Errorf("failed to set interface MTU: %w", err)
	}

	// Bring interface up
	if err = unix.IoctlSetInt(netfd, unix.SIOCSIFFLAGS, int(uintptr(unsafe.Pointer(&ifreq{
		Name:  ifr.Name,
		Flags: unix.IFF_UP | unix.IFF_RUNNING,
	})))); err != nil {
		return "", nil, fmt.Errorf("failed to bring interface up: %w", err)
	}

	return ifName, adapter, nil
}

func setAdapterMTU(netfd int, ifName string, mtu int) error {
	var err error

	if netfd == 0 {
		// Create network control socket
		netfd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
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

	if netfd == 0 {
		// Create network control socket
		netfd, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		if err != nil {
			return fmt.Errorf("failed to create network control socket: %w", err)
		}
		defer unix.Close(netfd)
	}

	// Set IP address
	var ifra ifreqAddr
	copy(ifra.Name[:], ifName)
	ifra.Addr.Family = unix.AF_INET
	copy(ifra.Addr.Addr[:], ipAddr.To4())

	if err = unix.IoctlSetInt(netfd, unix.SIOCSIFADDR, int(uintptr(unsafe.Pointer(&ifra)))); err != nil {
		return fmt.Errorf("SIOCSIFADDR: %w", err)
	}

	// Set netmask
	ifra.Addr.Family = unix.AF_INET
	copy(ifra.Addr.Addr[:], mask)

	if err = unix.IoctlSetInt(netfd, unix.SIOCSIFNETMASK, int(uintptr(unsafe.Pointer(&ifra)))); err != nil {
		return fmt.Errorf("SIOCSIFNETMASK: %w", err)
	}

	return nil
}

func addAdapterAddressV6(netfd int, ifName string, ipAddr net.IP, mask net.IPMask) error {
	var err error

	if netfd == 0 {
		netfd, err = unix.Socket(unix.AF_INET6, unix.SOCK_DGRAM, 0)
		if err != nil {
			return fmt.Errorf("failed to create network control socket: %w", err)
		}
		defer unix.Close(netfd)
	}

	var ifra6 in6_ifreq
	copy(ifra6.Addr.addr[:], ipAddr.To16())

	ones, _ := mask.Size()
	ifra6.PrefixLen = uint32(ones)

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to get index of interface <%s>: %w", ifName, err)
	}
	ifra6.Ifindex = int32(iface.Index)

	if err = unix.IoctlSetInt(netfd, unix.SIOCSIFADDR, int(uintptr(unsafe.Pointer(&ifra6)))); err != nil {
		return fmt.Errorf("SIOCSIFADDR: %w", err)
	}

	return nil
}

// getAdapterAddress retrieves the best adapter address for the given family, to be used
// immediately in order to establish an outbound connection.
func getAdapterAddress(ifName string, family int) (net.IP, *net.IPNet, error) {
	itf, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get interface: %w", err)
	}
	addrs, err := getIfAddrs(uint32(itf.Index), family)
	if err != nil {
		return nil, nil, err
	}
	if len(addrs) == 0 {
		return nil, nil, fmt.Errorf("no address found for interface: %s", ifName)
	}
	if family == unix.AF_INET {
		_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", addrs[0].IP, addrs[0].Prefixlen))
		return addrs[0].IP, ipNet, err
	}
	rank := func(a ifAddr) int {
		r := rankIPAddr(a.IP)
		if uint32(a.Flags)&unix.IFA_F_TEMPORARY != 0 {
			r++
		}
		return r
	}
	slices.SortStableFunc(addrs, func(a, b ifAddr) int {
		return rank(b) - rank(a)
	})

	_, ipNet, err := net.ParseCIDR(fmt.Sprintf("%s/%d", addrs[0].IP, addrs[0].Prefixlen))
	return addrs[0].IP, ipNet, err
}

type ifAddr struct {
	unix.IfAddrmsg
	IP net.IP
}

func getIfAddrs(ifIndex uint32, family int) ([]ifAddr, error) {
	tab, err := syscall.NetlinkRIB(unix.RTM_GETADDR, family)
	if err != nil {
		return nil, err
	}
	msgs, err := syscall.ParseNetlinkMessage(tab)
	if err != nil {
		return nil, err
	}
	var addrs []ifAddr
	for i := range msgs {
		m := &msgs[i]
		if m.Header.Type != unix.RTM_NEWADDR {
			continue
		}
		ifa := ifAddr{IfAddrmsg: *(*unix.IfAddrmsg)(unsafe.Pointer(&m.Data[0]))}
		if ifa.Index != ifIndex {
			continue
		}
		attrs, err := syscall.ParseNetlinkRouteAttr(m)
		if err != nil {
			continue
		}
		var local, addr net.IP
		for _, a := range attrs {
			switch a.Attr.Type {
			case unix.IFA_LOCAL:
				local = a.Value
			case unix.IFA_ADDRESS:
				addr = a.Value
			}
		}
		ip := local
		if ip == nil {
			ip = addr
		}
		if ip == nil {
			continue
		}
		ifa.IP = make(net.IP, len(ip))
		copy(ifa.IP[:], ip)
		addrs = append(addrs, ifa)
	}
	return addrs, nil
}
