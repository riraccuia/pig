//go:build windows && !unix

package network

import (
	"fmt"
	"net"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

func dialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	dialer := net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Unix-specific socket options
				windows.SetsockoptInt(windows.Handle(fd), windows.SOL_SOCKET, windows.SO_REUSEADDR, 1)
				windows.SetsockoptInt(windows.Handle(fd), windows.IPPROTO_TCP, windows.TCP_NODELAY, 1)
			})
		},
		Timeout: 5 * time.Second,
	}

	if laddr != nil {
		dialer.LocalAddr = laddr
	}

	conn, err := dialer.Dial(network, raddr.String())
	if err != nil {
		return nil, err
	}

	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("failed to convert to TCPConn")
	}

	return tcpConn, nil
}
