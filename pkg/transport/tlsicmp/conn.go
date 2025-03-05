package tlsicmp

import (
	"context"
	"crypto/tls"

	"github.com/riraccuia/pig/pkg/transport"
)

// conn implements transport.Conn and net.Conn by wrapping an ICMP connection with TLS
type conn struct {
	*tls.Conn
	// icmpConn transport.Conn
}

// newConn creates a new TLS-over-ICMP connection
func newConn(icmpConn transport.Conn, tlsConfig *tls.Config, isClient bool) (*conn, error) {
	c := &conn{}

	// Create TLS connection using our conn as the underlying transport
	switch isClient {
	case true:
		c.Conn = tls.Client(icmpConn, tlsConfig)
	case false:
		c.Conn = tls.Server(icmpConn, tlsConfig)
	}

	// Perform TLS handshake
	if err := c.Conn.Handshake(); err != nil {
		transport.Logger.Errorf("failed to handshake: %v", err)
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
