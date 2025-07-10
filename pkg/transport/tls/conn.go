package tls

import (
	"context"
	"crypto/tls"

	"github.com/riraccuia/pig/pkg/transport"
)

type TLSConn struct {
	*tls.Conn
}

func NewTLSConn(conn *tls.Conn) *TLSConn {
	return &TLSConn{Conn: conn}
}

func (t *TLSConn) IsStreamed() bool {
	return false
}

func (t *TLSConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	// TLS connections are already streams
	return nil, transport.ErrNotImplemented
}

func (t *TLSConn) NewStream(ctx context.Context) (transport.Stream, error) {
	// TLS connections are already streams
	return nil, transport.ErrNotImplemented
}

// Implement Stream interface methods
func (t *TLSConn) Flush() {
	// TLS connections don't need explicit flushing
}
