//go:build windows
// +build windows

package win

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitializeIpForwardRow = modiphlpapi.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2  = modiphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2  = modiphlpapi.NewProc("DeleteIpForwardEntry2")
	procGetBestRoute2          = modiphlpapi.NewProc("GetBestRoute2")
)

const (
	apiInitializeIpForwardEntry = "iphlpapi.dll!InitializeIpForwardEntry"
	apiCreateIpForwardEntry2    = "iphlpapi.dll!CreateIpForwardEntry2"
	apiDeleteIpForwardEntry2    = "iphlpapi.dll!DeleteIpForwardEntry2"
	apiGetBestRoute2            = "iphlpapi.dll!GetBestRoute2"
)

// InitializeIpForwardEntry initializes a MIB_IPFORWARD_ROW2 structure with default values.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-initializeipforwardentry.
func InitializeIpForwardEntry(row *windows.MibIpForwardRow2) error {
	ret, _, _ := procInitializeIpForwardRow.Call(uintptr(unsafe.Pointer(row)))
	if ret != 0 {
		return newReturnCodeError(apiInitializeIpForwardEntry, ret)
	}
	return nil
}

// CreateIpForwardEntry2 creates a route entry in the IP routing table.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2.
func CreateIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	ret, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if ret != 0 {
		return newReturnCodeError(apiCreateIpForwardEntry2, ret)
	}
	return nil
}

// DeleteIpForwardEntry2 deletes a route entry in the IP routing table.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-deleteipforwardentry2.
func DeleteIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	ret, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if ret != 0 {
		return newReturnCodeError(apiDeleteIpForwardEntry2, ret)
	}
	return nil
}

// GetBestRoute2 retrieves the best route to a destination address.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getbestroute2.
func GetBestRoute2(
	interfaceLuid *uint64,
	interfaceIndex uint32,
	sourceAddress *windows.RawSockaddrInet,
	destinationAddress *windows.RawSockaddrInet,
	addressSortOptions uint32,
	bestRoute *windows.MibIpForwardRow2,
	bestSourceAddress *windows.RawSockaddrInet,
) error {
	var (
		luidPtr   uintptr
		srcPtr    uintptr
		dstPtr    uintptr
		bestSrcPt uintptr
	)

	if interfaceLuid != nil {
		luidPtr = uintptr(unsafe.Pointer(interfaceLuid))
	}
	if sourceAddress != nil {
		srcPtr = uintptr(unsafe.Pointer(sourceAddress))
	}
	if destinationAddress != nil {
		dstPtr = uintptr(unsafe.Pointer(destinationAddress))
	}
	if bestSourceAddress != nil {
		bestSrcPt = uintptr(unsafe.Pointer(bestSourceAddress))
	}

	ret, _, _ := procGetBestRoute2.Call(
		luidPtr,
		uintptr(interfaceIndex),
		srcPtr,
		dstPtr,
		uintptr(addressSortOptions),
		uintptr(unsafe.Pointer(bestRoute)),
		bestSrcPt,
	)
	if ret != 0 {
		return newReturnCodeError(apiGetBestRoute2, ret)
	}
	return nil
}
