package network

import (
	"net"
)

// DialTCP uses a net.Dialer to dial a TCP connection and sets the SO_REUSEADDR and TCP_NODELAY options.
func DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	return dialTCP(network, laddr, raddr)
}
