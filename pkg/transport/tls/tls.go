package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/transport"
)

type TLSConn struct {
	*tls.Conn
}

type TLSListener struct {
	listener net.Listener
}

func NewTLSConn(conn *tls.Conn) *TLSConn {
	return &TLSConn{Conn: conn}
}

func NewTLSListener(listener net.Listener) *TLSListener {
	return &TLSListener{listener: listener}
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

func (t *TLSListener) Accept() (net.Conn, error) {
	conn, err := t.listener.Accept()
	if err != nil {
		return nil, err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("accepted connection is not a TLS connection")
	}
	return NewTLSConn(tlsConn), nil
}

func (t *TLSListener) Close() error {
	return t.listener.Close()
}

func GetClientDialFunc(ctx context.Context, logger *log.Logger, config *config.Config, tlsConfig *tls.Config) func() (transport.Conn, error) {
	return func() (transport.Conn, error) {
		addr := fmt.Sprintf("%s:%d", config.Target.Address, config.Target.Port)
		dialer := &net.Dialer{}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig.Clone())
		if err != nil {
			return nil, fmt.Errorf("failed to establish TLS connection: %w", err)
		}
		return NewTLSConn(conn), nil
	}
}

func GetServerListenFunc(ctx context.Context, logger *log.Logger, config *config.Config, tlsConfig *tls.Config) func() (transport.Listener, error) {
	return func() (transport.Listener, error) {
		addr := fmt.Sprintf(":%d", config.Target.Port)
		listener, err := tls.Listen("tcp", addr, tlsConfig.Clone())
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS listener: %w", err)
		}
		return NewTLSListener(listener), nil
	}
}
