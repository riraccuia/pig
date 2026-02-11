//go:build windows && !unix

package network

import (
	"context"
	"fmt"
	"net"
	"syscall"

	"golang.org/x/sys/windows"
)

func dialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	dialer := net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR
				windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
			})
		},
	}

	if laddr != nil {
		dialer.LocalAddr = laddr
	}

	conn, err := dialer.Dial(network, raddr.String())
	if err != nil {
		return nil, err
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("failed to convert to UDPConn")
	}

	return udpConn, nil
}

func listenUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR for Windows (equivalent to SO_REUSEADDR + SO_REUSEPORT on Unix)
				windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
			})
		},
	}

	conn, err := lc.ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, err
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("failed to convert to UDPConn")
	}

	return udpConn, nil
}
