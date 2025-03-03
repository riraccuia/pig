//go:build windows
// +build windows

package adapter

import (
	"fmt"
	"net"
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

var (
	// modiphlpapi provides access to the Windows IP Helper API.
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	// Windows API function pointers for network configuration.
	procAddIPAddress               = modiphlpapi.NewProc("AddIPAddress")
	procInitializeIpInterfaceEntry = modiphlpapi.NewProc("InitializeIpInterfaceEntry")
	procSetIpInterfaceEntry        = modiphlpapi.NewProc("SetIpInterfaceEntry")
)

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
		return fmt.Errorf("interface name cannot be empty")
	}

	// Get interface index
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface: %v", err)
	}

	// Parse IP and network
	ip, ipNet, err := net.ParseCIDR(config.Address)
	if err != nil {
		return fmt.Errorf("failed to parse address: %v", err)
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		return fmt.Errorf("invalid IPv4 address")
	}

	if err := setIPAddress(iface.Index, ipv4, ipNet.Mask); err != nil {
		return fmt.Errorf("failed to set IP address: %v", err)
	}

	if err := setMTU(iface.Index, config.MTU); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	return nil
}

// setIPAddress assigns an IPv4 address and subnet mask to a network interface.
// It uses the Windows AddIPAddress API to configure the interface.
//
// Parameters:
//   - ifIndex: The interface index to configure
//   - ip: The IPv4 address to assign
//   - mask: The subnet mask to apply
//
// Returns:
//   - error: nil if successful, otherwise an error describing what went wrong
func setIPAddress(ifIndex int, ip net.IP, mask net.IPMask) error {
	// Prepare IP address structure
	ipAddr := InAddr{}
	ipAddr.SAddr = uint32(ip[3]) | uint32(ip[2])<<8 | uint32(ip[1])<<16 | uint32(ip[0])<<24

	// Prepare subnet mask structure
	maskAddr := InAddr{}
	maskAddr.SAddr = uint32(mask[3]) | uint32(mask[2])<<8 | uint32(mask[1])<<16 | uint32(mask[0])<<24

	var nteContext uint32
	var nteInstance uint32

	ret, _, err := procAddIPAddress.Call(
		uintptr(unsafe.Pointer(&ipAddr)),
		uintptr(unsafe.Pointer(&maskAddr)),
		uintptr(ifIndex),
		uintptr(unsafe.Pointer(&nteContext)),
		uintptr(unsafe.Pointer(&nteInstance)),
	)

	if ret != 0 {
		return fmt.Errorf("AddIPAddress failed: %v", err)
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

	ret, _, err := procInitializeIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	if ret != 0 {
		return fmt.Errorf("InitializeIpInterfaceEntry failed: %v", err)
	}

	row.Family = windows.AF_INET
	row.InterfaceIndex = NET_IFINDEX(ifIndex)
	row.NlMtu = uint32(mtu)

	ret, _, err = procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	if ret != 0 {
		return fmt.Errorf("SetIpInterfaceEntry failed: %v", err)
	}

	return nil
}
