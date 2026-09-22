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

//go:build windows
// +build windows

package win

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modiphlpapi                     = windows.NewLazySystemDLL("iphlpapi.dll")
	procInitializeIpForwardRow      = modiphlpapi.NewProc("InitializeIpForwardEntry")
	procCreateIpForwardEntry2       = modiphlpapi.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2       = modiphlpapi.NewProc("DeleteIpForwardEntry2")
	procGetBestRoute2               = modiphlpapi.NewProc("GetBestRoute2")
	procGetIpNetEntry2              = modiphlpapi.NewProc("GetIpNetEntry2")
	procGetIpNetTable2              = modiphlpapi.NewProc("GetIpNetTable2")
	procConvertInterfaceLuidToIndex = modiphlpapi.NewProc("ConvertInterfaceLuidToIndex")
	procConvertInterfaceIndexToLuid = modiphlpapi.NewProc("ConvertInterfaceIndexToLuid")
	procConvertInterfaceNameToLuidW = modiphlpapi.NewProc("ConvertInterfaceNameToLuidW")
	procConvertInterfaceLuidToNameW = modiphlpapi.NewProc("ConvertInterfaceLuidToNameW")
)

// MibIpNetRow2 stores information about a neighbor IP address.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipnet_row2.
type MibIpNetRow2 struct {
	Address               windows.RawSockaddrInet6
	InterfaceIndex        uint32
	InterfaceLuid         uint64
	PhysicalAddress       [32]byte
	PhysicalAddressLength uint32
	State                 uint32
	Flags                 uint8
	_                     [3]byte
	ReachabilityTime      uint32
}

// MibIpNetTable2 contains a table of neighbor IP address entries.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/ns-netioapi-mib_ipnet_table2.
type MibIpNetTable2 struct {
	NumEntries uint32
	_          [4]byte
	Table      [1]MibIpNetRow2
}

// Rows returns the neighbor IP address entries in the table.
func (t *MibIpNetTable2) Rows() []MibIpNetRow2 {
	if t == nil || t.NumEntries == 0 {
		return nil
	}
	return unsafe.Slice(&t.Table[0], t.NumEntries)
}

// InitializeIpForwardEntry initializes a MIB_IPFORWARD_ROW2 structure with default values.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-initializeipforwardentry.
func InitializeIpForwardEntry(row *windows.MibIpForwardRow2) error {
	// procInitializeIpForwardRow.Call returns no value, so we don't need to check the return value
	procInitializeIpForwardRow.Call(uintptr(unsafe.Pointer(row)))
	return nil
}

// CreateIpForwardEntry2 creates a route entry in the IP routing table.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-createipforwardentry2.
func CreateIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	ret, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if ret != 0 {
		return newReturnCodeError("CreateIpForwardEntry2", ret)
	}
	return nil
}

// DeleteIpForwardEntry2 deletes a route entry in the IP routing table.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-deleteipforwardentry2.
func DeleteIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	ret, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if ret != 0 {
		return newReturnCodeError("DeleteIpForwardEntry2", ret)
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
		return newReturnCodeError("GetBestRoute2", ret)
	}
	return nil
}

// GetIpForwardTable2 retrieves the IP routing table for the given address family.
// The caller must free the returned table with FreeMibTable.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipforwardtable2.
func GetIpForwardTable2(family uint16) (*windows.MibIpForwardTable2, error) {
	var table *windows.MibIpForwardTable2
	err := windows.GetIpForwardTable2(family, &table)
	if err != nil {
		return nil, apiErrorFromErr("GetIpForwardTable2", err)
	}
	return table, nil
}

// FreeMibTable frees memory allocated by GetIpForwardTable2, GetIpNetTable2, and related MIB APIs.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-freemibtable.
func FreeMibTable(memory unsafe.Pointer) {
	if memory == nil {
		return
	}
	windows.FreeMibTable(memory)
}

// GetIpNetTable2 retrieves the IP neighbor table on the local computer.
// The caller must free the returned table with FreeMibTable.
// ERROR_NOT_FOUND is treated as success with an empty table (no neighbor entries).
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipnettable2.
func GetIpNetTable2(family uint16) (*MibIpNetTable2, error) {
	var table *MibIpNetTable2
	ret, _, _ := procGetIpNetTable2.Call(
		uintptr(family),
		uintptr(unsafe.Pointer(&table)),
	)
	// NO_ERROR and ERROR_NOT_FOUND both indicate a successful call.
	if ret != 0 && windows.Errno(ret) != windows.ERROR_NOT_FOUND {
		return nil, newReturnCodeError("GetIpNetTable2", ret)
	}
	return table, nil
}

// NotifyRouteChange2 registers a callback for IPv4/IPv6 route table changes.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-notifyroutechange2.
func NotifyRouteChange2(
	family uint16,
	callback uintptr,
	callerContext unsafe.Pointer,
	initialNotification bool,
) (windows.Handle, error) {
	var notificationHandle windows.Handle
	err := windows.NotifyRouteChange2(family, callback, callerContext, initialNotification, &notificationHandle)
	if err != nil {
		return 0, apiErrorFromErr("NotifyRouteChange2", err)
	}
	return notificationHandle, nil
}

// CancelMibChangeNotify2 cancels a notification registered with NotifyRouteChange2.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-cancelmibchangenotify2.
func CancelMibChangeNotify2(notificationHandle windows.Handle) error {
	if notificationHandle == 0 {
		return nil
	}
	err := windows.CancelMibChangeNotify2(notificationHandle)
	if err != nil {
		return apiErrorFromErr("CancelMibChangeNotify2", err)
	}
	return nil
}

// GetIpNetEntry2 retrieves information for a neighbor IP address entry on the local computer.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-getipnetentry2.
func GetIpNetEntry2(row *MibIpNetRow2) error {
	ret, _, _ := procGetIpNetEntry2.Call(uintptr(unsafe.Pointer(row)))
	if ret != 0 {
		return newReturnCodeError("GetIpNetEntry2", ret)
	}
	return nil
}

// ConvertInterfaceLuidToIndex converts a LUID to an interface index.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtoindex.
func ConvertInterfaceLuidToIndex(luid uint64) (uint32, error) {
	var index uint32
	ret, _, _ := procConvertInterfaceLuidToIndex.Call(uintptr(unsafe.Pointer(&luid)), uintptr(unsafe.Pointer(&index)))
	if ret != 0 {
		return 0, newReturnCodeError("ConvertInterfaceLuidToIndex", ret)
	}
	return index, nil
}

// ConvertInterfaceIndexToLuid converts an interface index to a LUID.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceindextoluid.
func ConvertInterfaceIndexToLuid(index uint32) (uint64, error) {
	var luid uint64
	ret, _, _ := procConvertInterfaceIndexToLuid.Call(uintptr(index), uintptr(unsafe.Pointer(&luid)))
	if ret != 0 {
		return 0, newReturnCodeError("ConvertInterfaceIndexToLuid", ret)
	}
	return luid, nil
}

// ConvertInterfaceNameToLuidW converts a NULL-terminated Unicode interface name to a LUID.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfacenametoluidw.
func ConvertInterfaceNameToLuidW(name string) (uint64, error) {
	var (
		luid  uint64
		wname = windows.StringToUTF16Ptr(name)
	)
	ret, _, _ := procConvertInterfaceNameToLuidW.Call(uintptr(unsafe.Pointer(wname)), uintptr(unsafe.Pointer(&luid)))
	if ret != 0 {
		return 0, newReturnCodeError("ConvertInterfaceNameToLuidW", ret)
	}
	return luid, nil
}

// ConvertInterfaceLuidToNameW converts a locally unique identifier (LUID) for a network interface to the Unicode interface name.
// See: https://learn.microsoft.com/en-us/windows/win32/api/netioapi/nf-netioapi-convertinterfaceluidtonamew.
func ConvertInterfaceLuidToNameW(luid uint64) (string, error) {
	var name [windows.IF_MAX_STRING_SIZE + 1]uint16
	ret, _, _ := procConvertInterfaceLuidToNameW.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&name[0])),
		uintptr(len(name)),
	)
	if ret != 0 {
		return "", newReturnCodeError("ConvertInterfaceLuidToNameW", ret)
	}
	return windows.UTF16ToString(name[:]), nil
}

func apiErrorFromErr(apiName string, err error) error {
	var errno windows.Errno
	var returnCode uintptr
	if errors.As(err, &errno) {
		returnCode = uintptr(errno)
	}
	return &APIError{
		APIName:    apiName,
		ReturnCode: returnCode,
		Cause:      err,
	}
}
