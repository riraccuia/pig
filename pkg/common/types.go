package common

import (
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/packet"
)

const (
	DefaultQueueSize     = 256
	DefaultConnectOffset = time.Millisecond * 500
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
	SetLevel(level string)
	Info(args ...any)
	Infof(format string, args ...any)
	Error(args ...any)
	Errorf(format string, args ...any)
	Debug(args ...any)
	Debugf(format string, args ...any)
	Fatal(args ...any)
	Fatalf(format string, args ...any)
	Trace(args ...any)
	Tracef(format string, args ...any)
}
