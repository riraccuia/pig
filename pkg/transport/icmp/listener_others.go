//go:build !darwin
// +build !darwin

package icmp

import (
	"fmt"
	"net"
)

type ipConn struct {
	*net.IPConn
}

func newIcmpIPConn(bindAddr *net.IPAddr, iface *net.Interface, isServer bool) (*ipConn, error) {
	conn, err := net.ListenIP("ip4:icmp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create ICMP socket: %w", err)
	}
	return &ipConn{
		IPConn: conn,
	}, nil
}
