package adapter

import (
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
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

type ifreqMTU struct {
	Name [unix.IFNAMSIZ]byte
	MTU  int32
	pad  [8]byte
}

// findAvailableTUNName tries to find an available TUN interface name
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
			return "", nil, fmt.Errorf("failed to create TUN queue: %w", err)
		}
		adapter.queues = append(adapter.queues, fd)
	}

	// Get interface name (in case kernel modified it)
	ifName = unix.ByteSliceToString(ifr.Name[:])

	// Create network control socket
	netfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create network control socket: %w", err)
	}
	defer unix.Close(netfd)

	// Parse IP and create netmask
	ip, ipNet, err := net.ParseCIDR(config.Address)
	if err != nil {
		return "", nil, fmt.Errorf("invalid CIDR address: %w", err)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return "", nil, fmt.Errorf("IPv6 is not supported, got: %s", config.Address)
	}

	// Set IP address
	var ifra ifreqAddr
	copy(ifra.Name[:], ifName)
	ifra.Addr.Family = unix.AF_INET
	copy(ifra.Addr.Addr[:], ipv4)

	if err = unix.IoctlSetInt(netfd, unix.SIOCSIFADDR, int(uintptr(unsafe.Pointer(&ifra)))); err != nil {
		return "", nil, fmt.Errorf("failed to set IP address: %w", err)
	}

	// Set netmask
	ifra.Addr.Family = unix.AF_INET
	copy(ifra.Addr.Addr[:], ipNet.Mask)

	if err = unix.IoctlSetInt(netfd, unix.SIOCSIFNETMASK, int(uintptr(unsafe.Pointer(&ifra)))); err != nil {
		return "", nil, fmt.Errorf("failed to set netmask: %w", err)
	}

	// Set MTU
	if config.MTU == 0 {
		config.MTU = 1300
	}

	var ifrm ifreqMTU
	copy(ifrm.Name[:], ifName)
	ifrm.MTU = int32(config.MTU)

	if err = unix.IoctlSetInt(netfd, unix.SIOCSIFMTU, int(uintptr(unsafe.Pointer(&ifrm)))); err != nil {
		return "", nil, fmt.Errorf("failed to set MTU: %w", err)
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

type tunAdapter struct {
	queues  []io.ReadWriteCloser
	devName string
}

func (a *tunAdapter) NewQueue(ifr ifreq, id int) (io.ReadWriteCloser, error) {
	queueFd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	if err = unix.IoctlSetInt(queueFd, TUNSETIFF, int(uintptr(unsafe.Pointer(&ifr)))); err != nil {
		return nil, fmt.Errorf("failed to create TUN queue: %w", err)
	}

	err = unix.SetNonblock(queueFd, true)
	if err != nil {
		return nil, fmt.Errorf("failed to set non-blocking mode: %w", err)
	}

	return os.NewFile(uintptr(queueFd), fmt.Sprintf("/dev/net/tun/%v-queue%v", a.devName, id)), nil
}

func (a *tunAdapter) Write(p []byte) (n int, err error) {
	return a.queues[0].Write(p)
}

func (a *tunAdapter) Read(p []byte) (n int, err error) {
	return a.queues[0].Read(p)
}

func (a *tunAdapter) Close() error {
	for _, fd := range a.queues {
		fd.Close()
	}
	return nil
}
