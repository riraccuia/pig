//go:build !windows || unix

package network

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
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

	if laddr == nil {
		return dialTCPOnce(&dialer, network, raddr)
	}

	dialer.LocalAddr = laddr

	var listener *net.TCPListener
	var err error
	listener, err = listenTCP(network, laddr)
	if err != nil {
		return nil, err
	}
	defer listener.Close()

	type acceptResult struct {
		conn *net.TCPConn
		err  error
	}
	acceptCh := make(chan acceptResult, 1)
	go func() {
		var accepted net.Conn
		var acceptErr error
		accepted, acceptErr = listener.Accept()
		if acceptErr != nil {
			acceptCh <- acceptResult{err: acceptErr}
			return
		}
		acceptedTCP, ok := accepted.(*net.TCPConn)
		if !ok {
			accepted.Close()
			acceptCh <- acceptResult{err: fmt.Errorf("failed to convert to TCPConn")}
			return
		}
		acceptCh <- acceptResult{conn: acceptedTCP}
	}()

	deadline := time.Now().Add(dialer.Timeout)
	for {
		select {
		case accepted := <-acceptCh:
			if accepted.err != nil {
				return nil, accepted.err
			}
			if accepted.conn == nil {
				return nil, fmt.Errorf("accept returned nil connection")
			}
			return accepted.conn, nil
		default:
		}

		var conn *net.TCPConn
		conn, err = dialTCPOnce(&dialer, network, raddr)
		if err == nil {
			select {
			case accepted := <-acceptCh:
				if accepted.conn != nil {
					accepted.conn.Close()
				}
			default:
			}
			return conn, nil
		}

		if !isConnRefused(err) {
			return nil, err
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		runtime.Gosched()
	}
}

func isConnRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

func dialTCPOnce(dialer *net.Dialer, network string, raddr *net.TCPAddr) (*net.TCPConn, error) {
	var conn net.Conn
	var err error
	conn, err = dialer.Dial(network, raddr.String())
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

func listenTCP(network string, laddr *net.TCPAddr) (*net.TCPListener, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
			})
		},
	}

	var listener net.Listener
	var err error
	listener, err = lc.Listen(context.Background(), network, laddr.String())
	if err != nil {
		return nil, err
	}

	tcpListener, ok := listener.(*net.TCPListener)
	if !ok {
		listener.Close()
		return nil, fmt.Errorf("failed to convert to TCPListener")
	}
	return tcpListener, nil
}

func CreateTCPSocket(sourcePort int, targetIP net.IP, targetPort int) (conn net.Conn, fd int, err error) {
	var (
		clientsock int
	)

	family := unix.AF_INET
	if targetIP.To4() == nil {
		family = unix.AF_INET6
	}

	if clientsock, err = unix.Socket(family, unix.SOCK_STREAM, unix.IPPROTO_IP); err != nil {
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

	var (
		serverAddr unix.Sockaddr
		bindAddr   unix.Sockaddr
	)
	switch family {
	case unix.AF_INET:
		sa := &unix.SockaddrInet4{Port: targetPort}
		copy(sa.Addr[:], targetIP.To4())
		sa.Port = targetPort
		serverAddr = sa
		bindAddr = &unix.SockaddrInet4{Port: sourcePort}
	case unix.AF_INET6:
		sa := &unix.SockaddrInet6{Port: targetPort}
		copy(sa.Addr[:], targetIP.To16())
		sa.Port = targetPort
		serverAddr = sa
		bindAddr = &unix.SockaddrInet6{Port: sourcePort}
	}

	err = unix.Bind(clientsock, bindAddr)
	if err != nil {
		unix.Close(clientsock)
		return
	}

	if err = unix.Connect(clientsock, serverAddr); err != nil {
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
