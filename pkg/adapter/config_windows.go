//go:build windows
// +build windows

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
	"runtime"
	"slices"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// MibIpinterfaceRow represents the Windows MIB_IPINTERFACE_ROW structure.
// It contains configuration parameters for an IP interface.
// See: https://learn.microsoft.com/en-us/windows-hardware/drivers/network/mib-ipinterface-row
type MibIpinterfaceRow struct {
	Family                               uint16
	InterfaceLuid                        uint64
	InterfaceIndex                       uint32
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

// MibUnicastipaddressRow represents the Windows MIB_UNICASTIPADDRESS_ROW structure.
// It contains information about a unicast IP address assigned to an interface.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_unicastipaddress_row
type MibUnicastipaddressRow struct {
	Address            [28]byte // SOCKADDR_INET
	InterfaceLuid      uint64
	InterfaceIndex     uint32
	PrefixOrigin       uint32
	SuffixOrigin       uint32
	ValidLifetime      uint32
	PreferredLifetime  uint32
	OnLinkPrefixLength uint8
	SkipAsSource       uint8
	DadState           uint32
	ScopeId            uint32
	CreationTimeStamp  int64
}

var (
	// modiphlpapi provides access to the Windows IP Helper API.
	modiphlpapi = windows.NewLazySystemDLL("iphlpapi.dll")

	// Windows API function pointers for network configuration.
	procInitializeIpInterfaceEntry      = modiphlpapi.NewProc("InitializeIpInterfaceEntry")
	procSetIpInterfaceEntry             = modiphlpapi.NewProc("SetIpInterfaceEntry")
	procInitializeUnicastIpAddressEntry = modiphlpapi.NewProc("InitializeUnicastIpAddressEntry")
	procCreateUnicastIpAddressEntry     = modiphlpapi.NewProc("CreateUnicastIpAddressEntry")
	procGetUnicastIpAddressEntry        = modiphlpapi.NewProc("GetUnicastIpAddressEntry")
	procNotifyUnicastIpAddressChange    = modiphlpapi.NewProc("NotifyUnicastIpAddressChange")
	procCancelMibChangeNotify2          = modiphlpapi.NewProc("CancelMibChangeNotify2")
	procConvertInterfaceLuidToIndex     = modiphlpapi.NewProc("ConvertInterfaceLuidToIndex")
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
func configureWinTun(adapter *NativeTun, config AdapterConfig) error {
	// Input validation
	if adapter == nil {
		return fmt.Errorf("configureWinTun: adapter cannot be nil")
	}

	// Get interface index
	iface, err := net.InterfaceByIndex(adapter.Index())
	if err != nil {
		return fmt.Errorf("configureWinTun: failed to get interface: %v", err)
	}

	for _, address := range config.Address {
		// Parse IP and network
		ip, ipNet, err := net.ParseCIDR(address)
		if err != nil {
			return fmt.Errorf("configureWinTun: failed to parse address: %v", err)
		}

		// Calculate prefix length from subnet mask
		prefixLen, _ := ipNet.Mask.Size()

		if err := setIPAddressUnicast(adapter, ip, uint8(prefixLen)); err != nil {
			return fmt.Errorf("configureWinTun: %v", err)
		}
	}

	if err := setMTU(iface.Index, config.MTU); err != nil {
		return fmt.Errorf("configureWinTun: %v", err)
	}

	return nil
}

// setIPAddressUnicast assigns an IPv4 or IPv6 address to a network interface using the CreateUnicastIpAddressEntry API.
// This is the modern replacement for the deprecated AddIPAddress function.
//
// Parameters:
//   - ifIndex: The interface index to configure
//   - ip: The IPv4 or IPv6 address to assign
//   - prefixLength: The subnet prefix length (e.g., 24 for 255.255.255.0 or 64 for ::/64)
//
// Returns:
//   - error: nil if successful, otherwise an error describing what went wrong
func setIPAddressUnicast(adapter *NativeTun, ip net.IP, prefixLength uint8) error {
	// The callback function specified in the Callback parameter must be implemented in the
	// same process as the application calling the NotifyUnicastIpAddressChange function
	// see: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyunicastipaddresschange
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Create and initialize the IP address row
	row := &windows.MibUnicastIpAddressRow{}

	procInitializeUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))

	switch {
	case ip.To4() != nil:
		addr := (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address))
		// Set the IP address family and value
		addr.Family = windows.AF_INET
		// Copy the IP address to the address buffer
		copy(addr.Addr[:], ip.To4())
	case ip.To16() != nil:
		addr := (*windows.RawSockaddrInet6)(unsafe.Pointer(&row.Address))
		// Set the IP address family and value
		addr.Family = windows.AF_INET6
		// Copy the IP address to the address buffer
		copy(addr.Addr[:], ip.To16())
	default:
		return fmt.Errorf("setIPAddressUnicast: invalid IP address: %s", ip)
	}

	// Set the interface index
	row.InterfaceIndex = uint32(adapter.Index())
	row.InterfaceLuid = adapter.LUID()
	// Set the subnet prefix length
	row.OnLinkPrefixLength = prefixLength
	// Set the DAD state
	row.DadState = windows.IpDadStatePreferred
	row.ValidLifetime = 0xffffffff
	row.PreferredLifetime = 0xffffffff

	readyChan, notificationHandle, err := getIPAddressReadyChan(adapter.LUID(), ip, int(row.Address.Family), 5*time.Second)
	defer clearNotificationHandle(notificationHandle)
	if err != nil {
		return fmt.Errorf("setIPAddressUnicast: %v", err)
	}

	// Create the unicast IP address entry
	ret, _, err := procCreateUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	if ret != windows.NO_ERROR {
		return fmt.Errorf("setIPAddressUnicast: CreateUnicastIpAddressEntry failed (ret: %d): %v", ret, err)
	}

	// Wait for the IP address to be ready
	err = <-readyChan
	if err != nil {
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
	row.InterfaceIndex = uint32(ifIndex)
	row.NlMtu = uint32(mtu)

	ret, _, err := procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	if ret != windows.NO_ERROR {
		return fmt.Errorf("setMTU: SetIpInterfaceEntry failed (ret: %d): %v", ret, err)
	}

	return nil
}

// getIPAddressReadyChan returns a channel that will be signaled when the IP address is ready on the specified interface.
// It uses NotifyUnicastIpAddressChange to receive notifications about IP address changes.
//
// Parameters:
//   - ifIndex: The interface index to monitor
//   - ip: The IPv4 address to wait for
//   - timeout: Maximum time to wait (use 0 for no timeout)
//
// Returns:
//   - doneChan: A channel that will be signaled when the IP address is ready
//   - notificationHandle: A handle to the notification
//   - error: nil if successful, otherwise an error describing what went wrong
func getIPAddressReadyChan(luid uint64, ip net.IP, family int, timeout time.Duration) (<-chan error, windows.Handle, error) {
	// Create a channel to signal when the address is ready
	doneChan := make(chan error, 1)
	var af *time.Timer
	if timeout > 0 {
		af = time.AfterFunc(timeout, func() {
			doneChan <- fmt.Errorf("waitForIPAddressReady: timeout waiting for IP address to be ready")
		})
	}

	// Create a callback function that will be called when IP address changes occur
	var notificationHandle windows.Handle

	// Define the callback function using windows.NewCallback
	callback := windows.NewCallback(func(callerContext unsafe.Pointer, row *windows.MibUnicastIpAddressRow, notificationType uint32) uintptr {
		if notificationType != windows.MibAddInstance {
			return 0
		}
		// Check if this is an address add notification for our interface
		if row.InterfaceLuid != luid {
			return 0
		}
		// Get the IP address from the notification
		var addrBytes []byte
		switch family {
		case int(windows.AF_INET):
			addrBytes = (*windows.RawSockaddrInet4)(unsafe.Pointer(&row.Address)).Addr[:]
		case int(windows.AF_INET6):
			addrBytes = (*windows.RawSockaddrInet6)(unsafe.Pointer(&row.Address)).Addr[:]
		}
		_ = addrBytes
		// Compare with our target IP
		// if net.IP(addrBytes).Equal(ip) {
		// Signal that the address is ready
		doneChan <- nil
		if af != nil {
			af.Stop()
		}
		// }
		return 0
	})

	// Register for IP address change notifications
	ret, _, err := procNotifyUnicastIpAddressChange.Call(
		uintptr(windows.AF_INET), // Family (IPv4)
		callback,                 // Callback function
		0,                        // CallerContext
		uintptr(0),               // InitialNotification (FALSE)
		uintptr(unsafe.Pointer(&notificationHandle)), // NotificationHandle
	)

	if ret != windows.NO_ERROR {
		return nil, 0, fmt.Errorf("waitForIPAddressReady: NotifyUnicastIpAddressChange failed (ret: %d): %v", ret, err)
	}

	return doneChan, notificationHandle, nil
}

// clearNotificationHandle cancels a notification for a specific IP address.
// It uses the CancelMibChangeNotify2 API to cancel the notification.
//
// Parameters:
//   - notificationHandle: The handle to the notification to cancel
func clearNotificationHandle(notificationHandle windows.Handle) {
	if notificationHandle == 0 {
		return
	}
	procCancelMibChangeNotify2.Call(uintptr(notificationHandle))
}

type ifAddr struct {
	IP        net.IP
	PrefixLen uint8
	Temporary bool
}

// getAdapterAddress retrieves the best adapter address for the given family, to be used
// immediately in order to establish an outbound connection.
func getAdapterAddress(ifName string, family int) (net.IP, *net.IPNet, error) {
	addrs, err := getIfAddrs(ifName, family)
	if err != nil {
		return nil, nil, err
	}
	if len(addrs) == 0 {
		return nil, nil, fmt.Errorf("no address found for interface: %s", ifName)
	}
	if family == int(windows.AF_INET) {
		return addrs[0].IP, ipNetFromAddr(addrs[0]), nil
	}
	rank := func(a ifAddr) int {
		r := rankIPAddr(a.IP)
		if a.Temporary {
			r++
		}
		return r
	}
	slices.SortStableFunc(addrs, func(a, b ifAddr) int {
		return rank(b) - rank(a)
	})
	return addrs[0].IP, ipNetFromAddr(addrs[0]), nil
}

func ipNetFromAddr(a ifAddr) *net.IPNet {
	bits := 128
	if a.IP.To4() != nil {
		bits = 32
	}
	return &net.IPNet{
		IP:   a.IP,
		Mask: net.CIDRMask(int(a.PrefixLen), bits),
	}
}

func getIfAddrs(ifName string, family int) ([]ifAddr, error) {
	aas, err := adapterAddresses(uint32(family))
	if err != nil {
		return nil, err
	}
	var addrs []ifAddr
	for _, aa := range aas {
		friendly := windows.UTF16PtrToString(aa.FriendlyName)
		adapterName := ""
		if aa.AdapterName != nil {
			adapterName = windows.BytePtrToString(aa.AdapterName)
		}
		if friendly != ifName && adapterName != ifName {
			continue
		}
		for u := aa.FirstUnicastAddress; u != nil; u = u.Next {
			if u.DadState == windows.IpDadStateTentative || u.DadState == windows.IpDadStateDuplicate || u.DadState == windows.IpDadStateInvalid {
				continue
			}
			ip := u.Address.IP()
			if ip == nil {
				continue
			}
			switch family {
			case int(windows.AF_INET):
				if ip.To4() == nil {
					continue
				}
				ip = ip.To4()
			case int(windows.AF_INET6):
				if ip.To4() != nil || ip.To16() == nil {
					continue
				}
				ip = ip.To16()
			default:
				continue
			}
			copied := make(net.IP, len(ip))
			copy(copied, ip)
			addrs = append(addrs, ifAddr{
				IP:        copied,
				PrefixLen: u.OnLinkPrefixLength,
				Temporary: u.SuffixOrigin == windows.IpSuffixOriginRandom,
			})
		}
		break
	}
	return addrs, nil
}

func adapterAddresses(family uint32) ([]*windows.IpAdapterAddresses, error) {
	var b []byte
	l := uint32(15000) // recommended initial size
	flags := uint32(windows.GAA_FLAG_INCLUDE_PREFIX | windows.GAA_FLAG_SKIP_ANYCAST | windows.GAA_FLAG_SKIP_MULTICAST | windows.GAA_FLAG_SKIP_DNS_SERVER)
	for {
		b = make([]byte, l)
		err := windows.GetAdaptersAddresses(family, flags, 0, (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])), &l)
		if err == nil {
			if l == 0 {
				return nil, nil
			}
			break
		}
		if err != windows.ERROR_BUFFER_OVERFLOW {
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
		if l <= uint32(len(b)) {
			return nil, fmt.Errorf("GetAdaptersAddresses: %w", err)
		}
	}
	var aas []*windows.IpAdapterAddresses
	for aa := (*windows.IpAdapterAddresses)(unsafe.Pointer(&b[0])); aa != nil; aa = aa.Next {
		aas = append(aas, aa)
	}
	return aas, nil
}
