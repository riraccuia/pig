package tlsicmp

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/transport"
)

var errDeadlineExceeded = errors.New("deadline exceeded")

// conn implements transport.Conn and net.Conn by wrapping an ICMP connection with TLS
type conn struct {
	tlsConn  *tls.Conn
	icmpConn transport.Conn
	// Deadline handling
	readDeadline  time.Time
	writeDeadline time.Time
}

// newConn creates a new TLS-over-ICMP connection
func newConn(icmpConn transport.Conn, tlsConfig *tls.Config, isClient bool) (*conn, error) {
	c := &conn{
		icmpConn: icmpConn,
	}

	// Create TLS connection using our conn as the underlying transport
	tlsConn := tls.Server(c, tlsConfig)
	if isClient {
		tlsConn = tls.Client(c, tlsConfig)
	}

	c.tlsConn = tlsConn

	// Perform TLS handshake
	if err := tlsConn.Handshake(); err != nil {
		icmpConn.Close()
		return nil, err
	}

	return c, nil
}

// IsStreamed implements transport.Conn
func (c *conn) IsStreamed() bool {
	return false
}

// Read implements both transport.Conn and net.Conn
func (c *conn) Read(b []byte) (n int, err error) {
	if !c.readDeadline.IsZero() && time.Now().After(c.readDeadline) {
		return 0, errDeadlineExceeded
	}
	return c.icmpConn.Read(b)
}

// Write implements both transport.Conn and net.Conn
func (c *conn) Write(b []byte) (n int, err error) {
	if !c.writeDeadline.IsZero() && time.Now().After(c.writeDeadline) {
		return 0, errDeadlineExceeded
	}
	return c.icmpConn.Write(b)
}

// Close implements both transport.Conn and net.Conn
func (c *conn) Close() error {
	if err := c.tlsConn.Close(); err != nil {
		return err
	}
	return c.icmpConn.Close()
}

// SetDeadline implements net.Conn
func (c *conn) SetDeadline(t time.Time) error {
	c.readDeadline = t
	c.writeDeadline = t
	return nil
}

// SetReadDeadline implements net.Conn
func (c *conn) SetReadDeadline(t time.Time) error {
	c.readDeadline = t
	return nil
}

// SetWriteDeadline implements net.Conn
func (c *conn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline = t
	return nil
}

// AcceptStream implements transport.Conn
func (c *conn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

// NewStream implements transport.Conn
func (c *conn) NewStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

// LocalAddr implements both transport.Conn and net.Conn
func (c *conn) LocalAddr() net.Addr {
	return c.icmpConn.LocalAddr()
}

// RemoteAddr implements both transport.Conn and net.Conn
func (c *conn) RemoteAddr() net.Addr {
	return c.icmpConn.RemoteAddr()
}
