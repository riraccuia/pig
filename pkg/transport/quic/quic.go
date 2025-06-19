package quic

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/transport"
	"golang.org/x/net/quic"
)

// A quic transport implementation that honors the transport.Listener and transport.Dialer interfaces
type QuicConn struct {
	conn *quic.Conn
}

type QuicTransport struct {
	endpoint *quic.Endpoint
}

func (c *QuicConn) IsStreamed() bool {
	return true
}

func NewQuicConn(conn *quic.Conn) *QuicConn {
	return &QuicConn{conn: conn}
}

func NewQuicTransport(endpoint *quic.Endpoint) *QuicTransport {
	return &QuicTransport{endpoint: endpoint}
}

func (c *QuicConn) Read(b []byte) (n int, err error) {
	return 0, transport.ErrNotImplemented
}

func (c *QuicConn) Write(b []byte) (n int, err error) {
	return 0, transport.ErrNotImplemented
}

func (c *QuicConn) LocalAddr() net.Addr {
	addr := c.conn.LocalAddr()
	return &net.UDPAddr{
		IP:   net.IPv4(addr.Addr().As4()[0], addr.Addr().As4()[1], addr.Addr().As4()[2], addr.Addr().As4()[3]),
		Port: int(addr.Port()),
	}
}

func (c *QuicConn) RemoteAddr() net.Addr {
	addr := c.conn.RemoteAddr()
	return &net.UDPAddr{
		IP:   net.IPv4(addr.Addr().As4()[0], addr.Addr().As4()[1], addr.Addr().As4()[2], addr.Addr().As4()[3]),
		Port: int(addr.Port()),
	}
}

func (c *QuicConn) Close() error {
	return c.conn.Close()
}

func (c *QuicConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return c.conn.AcceptStream(ctx)
}

func (c *QuicConn) NewStream(ctx context.Context) (transport.Stream, error) {
	return c.conn.NewStream(ctx)
}

func (c *QuicConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *QuicConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *QuicConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (t *QuicTransport) Accept(ctx context.Context) (transport.Conn, error) {
	conn, err := t.endpoint.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return &QuicConn{conn: conn}, nil
}

func (t *QuicTransport) Dial(ctx context.Context, network string, address string, config any) (transport.Conn, error) {
	conn, err := t.endpoint.Dial(ctx, network, address, config.(*quic.Config))
	if err != nil {
		return nil, err
	}
	return &QuicConn{conn: conn}, nil
}

func (t *QuicTransport) Close() error {
	return t.endpoint.Close(context.Background())
}

func GetClientDialFunc(ctx context.Context, logger *log.Logger, config *config.Config, tlsConfig *tls.Config) func() (transport.Conn, error) {
	return func() (transport.Conn, error) {
		endpoint, err := quic.Listen("udp", ":0", &quic.Config{TLSConfig: tlsConfig})
		if err != nil {
			return nil, fmt.Errorf("failed to listen on endpoint: %w", err)
		}
		conn, err := endpoint.Dial(
			ctx,
			"udp",
			fmt.Sprintf("%s:%d", config.Target.Address, config.Target.Port),
			&quic.Config{
				TLSConfig: tlsConfig.Clone(),
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
		}
		return NewQuicConn(conn), nil
	}
}

func GetServerListenFunc(ctx context.Context, logger *log.Logger, config *config.Config, tlsConfig *tls.Config) func() (transport.Listener, error) {
	return func() (transport.Listener, error) {
		endpoint, err := quic.Listen(
			"udp",
			fmt.Sprintf(":%d", config.Target.Port),
			&quic.Config{
				TLSConfig: tlsConfig.Clone(),
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on endpoint: %w", err)
		}
		return NewQuicTransport(endpoint), nil
	}
}
