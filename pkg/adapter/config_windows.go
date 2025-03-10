//go:build windows
// +build windows

package adapter

import (
	"fmt"
	"net"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// InAddr represents the Windows IN_ADDR structure.
// It is used to store IPv4 addresses in network byte order (big-endian).
type InAddr struct {
	SAddr uint32 // IPv4 address in network byte order
}

// NET_IFINDEX is a Windows type representing a network interface index.
type NET_IFINDEX uint32

// MibIpinterfaceRow represents the Windows MIB_IPINTERFACE_ROW structure.
// It contains configuration parameters for an IP interface.
// See: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/mib-ipinterface-row
type MibIpinterfaceRow struct {
	Family                               uint32
	InterfaceLuid                        uint64
	InterfaceIndex                       NET_IFINDEX
	MaxReassemblySize                    uint32
	InterfaceIdentifier                  uint64
	MinRouterAdvertisementInterval       uint32
	MaxRouterAdvertisementInterval       uint32
	AdvertisingEnabled                   uint8
	ForwardingEnabled                    uint8
	WeakHostSend                         uint8
	WeakHostReceive                      uint8
	UseAutomaticMetric                   uint8
	UseNeighborUnreachabilityDetection   uint8
	ManagedAddressConfigurationSupported uint8
	OtherStatefulConfigurationSupported  uint8
	AdvertiseDefaultRoute                uint8
	RouterDiscoveryBehavior              uint32
	DadTransmits                         uint32
	BaseReachableTime                    uint32
	RetransmitTime                       uint32
	PathMtuDiscoveryTimeout              uint32
	LinkLocalAddressBehavior             uint32
	LinkLocalAddressTimeout              uint32
	ZoneIndices                          [16]uint32
	SitePrefixLength                     uint32
	Metric                               uint32
	NlMtu                                uint32
	Connected                            uint8
	SupportsWakeUpPatterns               uint8
	SupportsNeighborDiscovery            uint8
	SupportsRouterDiscovery              uint8
	ReachableTime                        uint32
	TransmitOffload                      uint32
	ReceiveOffload                       uint32
	DisableDefaultRoutes                 uint8
}

// SOCKADDR_IN represents the Windows sockaddr_in structure for IPv4 addresses
type SOCKADDR_IN struct {
	Family uint16
	Port   uint16
	Addr   InAddr
	Zero   [8]byte
}

// SOCKADDR_INET represents the Windows SOCKADDR_INET union structure
// It can hold either IPv4 or IPv6 addresses
type SOCKADDR_INET struct {
	Ipv4 SOCKADDR_IN
	// IPv6 fields omitted as we're only using IPv4 in this implementation
	// Ipv6 SOCKADDR_IN6
}

// MibUnicastipaddressRow represents the Windows MIB_UNICASTIPADDRESS_ROW structure
// It contains information about a unicast IP address assigned to an interface
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_row
type MibUnicastipaddressRow struct {
	Address            SOCKADDR_INET
	InterfaceLuid      uint64
	InterfaceIndex     NET_IFINDEX
	PrefixOrigin       uint32
	SuffixOrigin       uint32
	ValidLifetime      uint32
	PreferredLifetime  uint32
	OnLinkPrefixLength uint8
	SkipAsSource       uint8
	DadState           uint32
	ScopeId            uint32
	CreationTimeStamp  uint64
}

var (
	// modiphlpapi provides access to the Windows IP Helper API.
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	// Windows API function pointers for network configuration.
	procInitializeIpInterfaceEntry      = modiphlpapi.NewProc("InitializeIpInterfaceEntry")
	procSetIpInterfaceEntry             = modiphlpapi.NewProc("SetIpInterfaceEntry")
	procInitializeUnicastIpAddressEntry = modiphlpapi.NewProc("InitializeUnicastIpAddressEntry")
	procCreateUnicastIpAddressEntry     = modiphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procNotifyUnicastIpAddressChange    = modiphlpapi.NewProc("NotifyUnicastIpAddressChange")
	procCancelMibChangeNotify2          = modiphlpapi.NewProc("CancelMibChangeNotify2")
)

// ipv4ToBytes converts a uint32 IP address in network byte order to a byte slice.
// This is useful for converting between Windows API representation and Go's net.IP.
func ipv4ToBytes(addr uint32) []byte {
	bytes := make([]byte, 4)
	bytes[0] = byte(addr >> 24)
	bytes[1] = byte(addr >> 16)
	bytes[2] = byte(addr >> 8)
	bytes[3] = byte(addr)
	return bytes
}

// bytesToIPv4 converts a Go net.IP (IPv4) to a uint32 in network byte order.
// This is useful for converting between Go's net.IP and Windows API representation.
func bytesToIPv4(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return uint32(ip[3]) | uint32(ip[2])<<8 | uint32(ip[1])<<16 | uint32(ip[0])<<24
}

// configureWinTun configures a WinTun adapter with the specified IP address and MTU.
// It sets both the IP address/subnet mask and the MTU value for the interface.
//
// Parameters:
//   - ifaceName: The name of the WinTun interface to configure
//   - config: The adapter configuration containing the IP address and MTU
//
// Returns:
//   - error: nil if successful, otherwise an error describing what went wrong
func configureWinTun(ifaceName string, config AdapterConfig) error {
	// Input validation
	if ifaceName == "" {
		return fmt.Errorf("configureWinTun: interface name cannot be empty")
	}

	// Get interface index
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("configureWinTun: failed to get interface: %v", err)
	}

	// Parse IP and network
	ip, ipNet, err := net.ParseCIDR(config.Address)
	if err != nil {
		return fmt.Errorf("configureWinTun: failed to parse address: %v", err)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("configureWinTun: invalid IPv4 address")
	}

	// Calculate prefix length from subnet mask
	prefixLen, _ := ipNet.Mask.Size()

	if err := setIPAddressUnicast(iface.Index, ipv4, uint8(prefixLen)); err != nil {
		return fmt.Errorf("configureWinTun: %v", err)
	}

	if err := setMTU(iface.Index, config.MTU); err != nil {
		return fmt.Errorf("configureWinTun: %v", err)
	}

	return nil
}

// setIPAddressUnicast assigns an IPv4 address to a network interface using the CreateUnicastIpAddressEntry API.
// This is the modern replacement for the deprecated AddIPAddress function.
//
// Parameters:
//   - ifIndex: The interface index to configure
//   - ip: The IPv4 address to assign
//   - prefixLength: The subnet prefix length (e.g., 24 for 255.255.255.0)
//
// Returns:
//   - error: nil if successful, otherwise an error describing what went wrong
func setIPAddressUnicast(ifIndex int, ip net.IP, prefixLength uint8) error {
	// Create and initialize the IP address row
	row := &MibUnicastipaddressRow{}

	procInitializeUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))

	// Set the interface index
	row.InterfaceIndex = NET_IFINDEX(ifIndex)

	// Set the IP address family and value
	row.Address.Ipv4.Family = windows.AF_INET
	// Convert IP to network byte order (big-endian)
	row.Address.Ipv4.Addr.SAddr = bytesToIPv4(ip)

	// Set the subnet prefix length
	row.OnLinkPrefixLength = prefixLength

	// Create the unicast IP address entry
	ret, _, err := procCreateUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	if ret != windows.NO_ERROR {
		return fmt.Errorf("setIPAddressUnicast: CreateUnicastIpAddressEntry failed (ret: %d): %v", ret, err)
	}

	// Wait for the IP address to be ready (with a 5-second timeout)
	if err := waitForIPAddressReady(ifIndex, ip, 5*time.Second); err != nil {
		return fmt.Errorf("setIPAddressUnicast: %v", err)
	}

	return nil
}

// setMTU configures the Maximum Transmission Unit (MTU) for a network interface.
// It uses the Windows SetIpInterfaceEntry API to set the MTU value.
//
// Parameters:
//   - ifIndex: The interface index to configure
//   - mtu: The MTU value to set
//
// Returns:
//   - error: nil if successful, otherwise an error describing what went wrong
func setMTU(ifIndex int, mtu int) error {
	row := &MibIpinterfaceRow{}

	procInitializeIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))

	row.Family = windows.AF_INET
	row.InterfaceIndex = NET_IFINDEX(ifIndex)
	row.NlMtu = uint32(mtu)

	ret, _, err := procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	if ret != windows.NO_ERROR {
		return fmt.Errorf("setMTU: SetIpInterfaceEntry failed (ret: %d): %v", ret, err)
	}

	return nil
}

// waitForIPAddressReady waits for the IP address to be ready on the specified interface.
// It uses NotifyUnicastIpAddressChange to receive notifications about IP address changes.
//
// Parameters:
//   - ifIndex: The interface index to monitor
//   - ip: The IPv4 address to wait for
//   - timeout: Maximum time to wait (use 0 for no timeout)
//
// Returns:
//   - error: nil if successful, otherwise an error describing what went wrong
func waitForIPAddressReady(ifIndex int, ip net.IP, timeout time.Duration) error {
	// Create a channel to signal when the address is ready
	readyChan := make(chan bool, 1)
	errorChan := make(chan error, 1)

	// Create a callback function that will be called when IP address changes occur
	var notificationHandle windows.Handle

	// Define the callback function using windows.NewCallback
	callback := windows.NewCallback(func(callerContext uintptr, row *MibUnicastipaddressRow, notificationType uint32) uintptr {
		// Check if this is an address add notification for our interface
		if notificationType == windows.MibAddInstance &&
			row.InterfaceIndex == NET_IFINDEX(ifIndex) {
			// Get the IP address from the notification
			addrBytes := ipv4ToBytes(row.Address.Ipv4.Addr.SAddr)

			// Compare with our target IP
			if net.IP(addrBytes).Equal(ip) {
				// Signal that the address is ready
				readyChan <- true
			}
		}
		return 0
	})

	// Register for IP address change notifications
	ret, _, err := procNotifyUnicastIpAddressChange.Call(
		uintptr(windows.AF_INET), // Family (IPv4)
		uintptr(callback),        // Callback function
		0,                        // CallerContext
		uintptr(0),               // InitialNotification (FALSE)
		uintptr(unsafe.Pointer(&notificationHandle)), // NotificationHandle
	)

	if ret != windows.NO_ERROR {
		return fmt.Errorf("waitForIPAddressReady: NotifyUnicastIpAddressChange failed (ret: %d): %v", ret, err)
	}

	// Make sure we clean up the notification when done
	defer func() {
		if notificationHandle != 0 {
			procCancelMibChangeNotify2.Call(uintptr(notificationHandle))
		}
	}()

	// Set up a timeout if requested
	var timeoutChan <-chan time.Time
	if timeout > 0 {
		timeoutChan = time.After(timeout)
	}

	// Wait for the address to be ready or timeout
	select {
	case <-readyChan:
		return nil
	case err := <-errorChan:
		return err
	case <-timeoutChan:
		return fmt.Errorf("waitForIPAddressReady: timeout waiting for IP address to be ready")
	}
}
