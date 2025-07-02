package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

var ErrNotImplemented = errors.New("not implemented")

type Stream interface {
	io.ReadWriteCloser
	Flush()
}

type Listener interface {
	Accept() (net.Conn, error)
	Close() error
}

type Dialer interface {
	Dial(ctx context.Context, network string, address string, config any) (Conn, error)
}

type Conn interface {
	IsStreamed() bool
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	AcceptStream(ctx context.Context) (Stream, error)
	NewStream(ctx context.Context) (Stream, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}
