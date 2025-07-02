package udp

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/transport"
)

// connection implements the transport.Conn interface
type connection struct {
	conn       net.PacketConn
	raddr      net.Addr
	readChan   chan []byte
	ctx        context.Context
	readBuffer []byte // Buffer for partially read data
}

func (c *connection) IsStreamed() bool {
	return false
}

func (c *connection) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *connection) NewStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *connection) Read(b []byte) (n int, err error) {
	// If we have leftover data from a previous read, use that first
	if len(c.readBuffer) > 0 {
		n = copy(b, c.readBuffer)
		if n < len(c.readBuffer) {
			// Buffer b was too small, keep the remaining data
			c.readBuffer = c.readBuffer[n:]
		} else {
			// All data was copied, clear the buffer
			c.readBuffer = nil
		}
		return n, nil
	}

	// No leftover data, read from channel
	select {
	case <-c.ctx.Done():
		return 0, fmt.Errorf("connection closed")
	case data, ok := <-c.readChan:
		if !ok {
			return 0, fmt.Errorf("connection closed")
		}
		n = copy(b, data)
		if n < len(data) {
			// Buffer b was too small, store the remaining data
			c.readBuffer = make([]byte, len(data)-n)
			copy(c.readBuffer, data[n:])
		}
		return n, nil
	}
}

func (c *connection) Write(b []byte) (n int, err error) {
	if c.raddr == nil {
		return 0, fmt.Errorf("no remote address set for UDP connection")
	}
	return c.conn.WriteTo(b, c.raddr)
}

func (c *connection) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *connection) RemoteAddr() net.Addr {
	return c.raddr
}

func (c *connection) SetDeadline(t time.Time) error {
	return c.conn.SetDeadline(t)
}

func (c *connection) SetReadDeadline(t time.Time) error {
	return c.conn.SetReadDeadline(t)
}

func (c *connection) SetWriteDeadline(t time.Time) error {
	return c.conn.SetWriteDeadline(t)
}

func (c *connection) Close() error {
	return c.conn.Close()
}
