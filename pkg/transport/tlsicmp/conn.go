package tlsicmp

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/transport"
)

// conn implements transport.Conn and net.Conn by wrapping an ICMP connection with TLS
type conn struct {
	*tls.Conn
	// icmpConn transport.Conn
}

// newConn creates a new TLS-over-ICMP connection
func newConn(icmpConn net.Conn, tlsConfig *tls.Config, isServer bool) (*conn, error) {
	icmpConn.SetReadDeadline(time.Now().Add(time.Second * 5))
	defer icmpConn.SetReadDeadline(time.Time{})

	c := &conn{}
	// Create TLS connection using our conn as the underlying transport
	switch isServer {
	case false:
		c.Conn = tls.Client(icmpConn, tlsConfig)
	case true:
		c.Conn = tls.Server(icmpConn, tlsConfig)
		// return c, nil
	}

	// Perform TLS handshake
	if err := c.Conn.Handshake(); err != nil {
		icmpConn.Close()
		return nil, err
	}

	return c, nil
}

// IsStreamed implements transport.Conn
func (c *conn) IsStreamed() bool {
	return false
}

// AcceptStream implements transport.Conn
func (c *conn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

// NewStream implements transport.Conn
func (c *conn) NewStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}
