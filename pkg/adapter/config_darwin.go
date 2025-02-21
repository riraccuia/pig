package adapter

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	CTLIOCGINFO      = 0xc0644e03
	CTLTYPE_NODE     = 1
	SYSPROTO_CONTROL = 2
	UTUN_OPT_IFNAME  = 2
)

type ifaliasreq struct {
	Name [unix.IFNAMSIZ]byte
	Addr unix.RawSockaddrInet4
	Mask unix.RawSockaddrInet4
	Dest unix.RawSockaddrInet4
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

	// Parse IP and create netmask
	ip, ipNet, err := net.ParseCIDR(config.Address)
	if err != nil {
		return "", nil, fmt.Errorf("invalid CIDR address: %w", err)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return "", nil, fmt.Errorf("IPv6 is not supported, got: %s", config.Address)
	}

	// Create network control socket, set FD_CLOEXEC to avoid leaking file descriptors
	netfd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.FD_CLOEXEC, unix.IPPROTO_IP)
	if err != nil {
		return "", nil, fmt.Errorf("failed to create network control socket: %w", err)
	}
	defer unix.Close(netfd)

	// default MTU to 1300 if not specified
	if config.MTU == 0 {
		config.MTU = 1300
	}

	mtuRequest := unix.IfreqMTU{}
	copy(mtuRequest.Name[:], ifName)
	mtuRequest.MTU = int32(config.MTU)

	if err = unix.IoctlSetIfreqMTU(netfd, &mtuRequest); err != nil {
		return "", nil, fmt.Errorf("failed to set interface MTU: %w", err)
	}

	// Prepare interface alias request
	var ifra ifaliasreq
	copy(ifra.Name[:], ifName)

	// Setup IP address
	ifra.Addr.Family = unix.AF_INET
	ifra.Addr.Len = unix.SizeofSockaddrInet4
	copy(ifra.Addr.Addr[:], ipv4)

	// Setup destination IP address
	ifra.Dest.Family = unix.AF_INET
	ifra.Dest.Len = unix.SizeofSockaddrInet4
	copy(ifra.Dest.Addr[:], ipv4)

	// Setup netmask
	ifra.Mask.Family = unix.AF_INET
	ifra.Mask.Len = unix.SizeofSockaddrInet4
	copy(ifra.Mask.Addr[:], ipNet.Mask)

	// Configure IP using SIOCAIFADDR, this is the socket option that sets the IP address
	if err = unix.IoctlSetInt(netfd, unix.SIOCAIFADDR, int(uintptr(unsafe.Pointer(&ifra)))); err != nil {
		return "", nil, fmt.Errorf("failed to set interface address: %w", err)
	}
	_ = ipNet

	adapter = &utunAdapter{
		fd: os.NewFile(uintptr(sockfd), ""),
	}

	return ifName, adapter, nil
}

// utunAdapter is a hack to work around the first 4 bytes "packet
// information" because there doesn't seem to be an IFF_NO_PI for darwin.
type utunAdapter struct {
	fd *os.File

	rMu  sync.Mutex
	rBuf []byte

	wMu  sync.Mutex
	wBuf []byte
}

func (t *utunAdapter) Read(to []byte) (int, error) {
	t.rMu.Lock()
	defer t.rMu.Unlock()

	if cap(t.rBuf) < len(to)+4 {
		t.rBuf = make([]byte, len(to)+4)
	}
	t.rBuf = t.rBuf[:len(to)+4]

	n, err := t.fd.Read(t.rBuf)
	copy(to, t.rBuf[4:])
	return n - 4, err
}

func (t *utunAdapter) Write(from []byte) (int, error) {

	if len(from) == 0 {
		return 0, syscall.EIO
	}

	t.wMu.Lock()
	defer t.wMu.Unlock()

	if cap(t.wBuf) < len(from)+4 {
		t.wBuf = make([]byte, len(from)+4)
	}
	t.wBuf = t.wBuf[:len(from)+4]

	// Determine the IP Family for the NULL L2 Header
	ipVer := from[0] >> 4
	if ipVer == 4 {
		t.wBuf[3] = syscall.AF_INET
	} else if ipVer == 6 {
		t.wBuf[3] = syscall.AF_INET6
	} else {
		return 0, errors.New("unable to determine IP version from packet")
	}

	copy(t.wBuf[4:], from)

	n, err := t.fd.Write(t.wBuf)
	return n - 4, err
}

func (t *utunAdapter) Close() error {
	return t.fd.Close()
}
