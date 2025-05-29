package conn

import (
	"fmt"
	"net"
)

type TCPListener struct {
	acceptChan chan net.Conn
	localAddr  *net.TCPAddr
}

func NewTCPListener(localAddr *net.TCPAddr) *TCPListener {
	return &TCPListener{
		acceptChan: make(chan net.Conn, 32),
		localAddr:  localAddr,
	}
}

func (l *TCPListener) Addr() net.Addr {
	return l.localAddr
}

func (l *TCPListener) Load(conn net.Conn) error {
	select {
	case l.acceptChan <- conn:
		return nil
	default:
		conn.Close()
		return fmt.Errorf("accept channel is full")
	}
}

func (l *TCPListener) Accept() (net.Conn, error) {
	conn, ok := <-l.acceptChan
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (l *TCPListener) Close() error {
	close(l.acceptChan)
	return nil
}

// DialTCP uses a net.Dialer to dial a TCP connection and sets the SO_REUSEADDR and TCP_NODELAY options.
func DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	return dialTCP(network, laddr, raddr)
}
