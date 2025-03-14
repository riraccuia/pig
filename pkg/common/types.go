package common

import (
	"net"

	"github.com/riraccuia/pig/pkg/packet"
)

const (
	QueueSize = 1024
)

type PacketQueue chan packet.IPv4Packet

type TunnelAdapter interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	IP() net.IP
	Name() string
	Index() int
}

type Logger interface {
	Info(args ...interface{})
	Infof(format string, args ...interface{})
	Error(args ...interface{})
	Errorf(format string, args ...interface{})
	Debug(args ...interface{})
	Debugf(format string, args ...interface{})
	Fatal(args ...interface{})
	Fatalf(format string, args ...interface{})
}
