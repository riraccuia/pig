package interfaces

import "net"

type TunnelAdapter interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	IP() net.IP
	Name() string
}
