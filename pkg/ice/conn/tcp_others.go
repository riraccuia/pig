//go:build !windows || unix

package conn

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func dialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	dialer := net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Unix-specific socket options
				unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				// unix.SetsockoptInt(int(fd), unix.IPPROTO_TCP, unix.TCP_NODELAY, 1)
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

func CreateTCPSocket(sourcePort int, targetIP net.IP, targetPort int) (conn net.Conn, fd int, err error) {
	var (
		clientsock int
		serveraddr unix.SockaddrInet4
	)

	if clientsock, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM, unix.IPPROTO_IP); err != nil {
		return
	}
	err = unix.SetsockoptInt(clientsock, unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
	if err != nil {
		unix.Close(clientsock)
		return
	}

	// Set socket to blocking mode
	if err = unix.SetNonblock(clientsock, false); err != nil {
		unix.Close(clientsock)
		return
	}

	// Set TCP_NODELAY to disable Nagle's algorithm
	if err = unix.SetsockoptInt(clientsock, unix.IPPROTO_TCP, unix.TCP_NODELAY, 1); err != nil {
		unix.Close(clientsock)
		return
	}

	serveraddr.Addr[0] = byte(targetIP[0])
	serveraddr.Addr[1] = byte(targetIP[1])
	serveraddr.Addr[2] = byte(targetIP[2])
	serveraddr.Addr[3] = byte(targetIP[3])

	serveraddr.Port = targetPort

	err = unix.Bind(clientsock, &unix.SockaddrInet4{
		Port: sourcePort,
	})
	if err != nil {
		unix.Close(clientsock)
		return
	}

	if err = unix.Connect(clientsock, &serveraddr); err != nil {
		unix.Close(clientsock)
		return
	}

	// create os.File from file descriptor
	file := os.NewFile(uintptr(clientsock), "")
	conn, err = net.FileConn(file)
	if err != nil {
		unix.Close(clientsock)
		return
	}

	fd = clientsock

	return
}

func ShutdownSocket(fd int) error {
	return unix.Shutdown(fd, unix.SHUT_RDWR)
}
