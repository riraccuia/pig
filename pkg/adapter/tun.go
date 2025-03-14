//go:build !windows
// +build !windows

package adapter

import (
	"net"
)

// Tunnel represents a generic tunnel interface
type Interface interface {
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
}

type TUNAdapter struct {
	iface  Interface
	ip     net.IP
	ifName string
}

func (t *TUNAdapter) Read(b []byte) (int, error) {
	return t.iface.Read(b)
}

func (t *TUNAdapter) Write(b []byte) (int, error) {
	return t.iface.Write(b)
}

func (t *TUNAdapter) Close() error {
	return t.iface.Close()
}

func (t *TUNAdapter) IP() net.IP {
	return t.ip
}

func (t *TUNAdapter) Name() string {
	return t.ifName
}

func (t *TUNAdapter) Index() int {
	iface, err := net.InterfaceByName(t.ifName)
	if err != nil {
		return -1
	}
	return iface.Index
}
