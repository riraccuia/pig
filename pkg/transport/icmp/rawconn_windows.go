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

package icmp

import (
	"fmt"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SIO_RCVALL / RCVALL_* are not in golang.org/x/sys/windows; values from MSDN
// (winsockx.h): SIO_RCVALL = _WSAIOW(IOC_VENDOR, 1).
const (
	SIO_RCVALL = windows.IOC_IN | windows.IOC_VENDOR | 1
	RCVALL_ON  = 1
)

// setupRawConn prepares ICMP send + receive sockets for Windows.
//
// Send uses the normal IPPROTO_ICMP socket without IP_HDRINCL so Winsock
// builds the IPv4 header.
//
// Receive uses a separate IPPROTO_IP socket with SIO_RCVALL: Windows icmp.sys
// otherwise intercepts Echo Replies before IPPROTO_ICMP sockets see them, so
// server→client data and ACKs never arrive.
func (l *sharedListener) setupRawConn(iface *net.Interface) error {
	if err := l.conn.SetWriteBuffer(defaultBufferSize); err != nil {
		return fmt.Errorf("failed to set write buffer: %w", err)
	}
	if err := l.conn.SetReadBuffer(defaultBufferSize); err != nil {
		return fmt.Errorf("failed to set read buffer: %w", err)
	}
	return l.setupRecvAll(iface)
}

func (l *sharedListener) setupRecvAll(iface *net.Interface) error {
	ip, err := rcvAllBindIP(l.localAddr, iface)
	if err != nil {
		return err
	}
	recv, err := net.ListenIP("ip4:0", &net.IPAddr{IP: ip})
	if err != nil {
		return fmt.Errorf("failed to create receive-all socket: %w", err)
	}
	if err := recv.SetReadBuffer(defaultBufferSize); err != nil {
		recv.Close()
		return fmt.Errorf("failed to set receive-all read buffer: %w", err)
	}
	if err := setRecvAll(recv); err != nil {
		recv.Close()
		return fmt.Errorf("failed to enable SIO_RCVALL: %w", err)
	}
	l.recvConn = recv
	l.logger.Infof("ICMP Windows receive-all enabled on %s", ip)
	return nil
}

func rcvAllBindIP(local *net.IPAddr, iface *net.Interface) (net.IP, error) {
	if local != nil {
		if ip := local.IP.To4(); ip != nil && !ip.IsUnspecified() {
			return ip, nil
		}
	}
	if iface != nil {
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("failed to list interface addresses: %w", err)
		}
		for _, addr := range addrs {
			ipnet, ok := addr.(*net.IPNet)
			if !ok || ipnet.IP.IsLoopback() {
				continue
			}
			if ip := ipnet.IP.To4(); ip != nil {
				return ip, nil
			}
		}
	}
	return nil, fmt.Errorf("SIO_RCVALL requires a specific IPv4 bind address; set --bind-adapter (or equivalent)")
}

func setRecvAll(conn *net.IPConn) error {
	raw, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var ioctlErr error
	if err := raw.Control(func(fd uintptr) {
		var bytesReturned uint32
		inBuf := uint32(RCVALL_ON)
		ioctlErr = windows.WSAIoctl(
			windows.Handle(fd),
			SIO_RCVALL,
			(*byte)(unsafe.Pointer(&inBuf)),
			uint32(unsafe.Sizeof(inBuf)),
			nil,
			0,
			&bytesReturned,
			nil,
			0,
		)
	}); err != nil {
		return err
	}
	return ioctlErr
}
