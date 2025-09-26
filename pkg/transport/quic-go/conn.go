package quicgo

import (
	"context"
	"net"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/riraccuia/pig/pkg/transport"
)

type QuicConn struct {
	conn *quic.Conn
}

type QuicStream struct {
	stream *quic.Stream
}

func (s *QuicStream) Read(p []byte) (n int, err error) {
	return s.stream.Read(p)
}

func (s *QuicStream) Write(p []byte) (n int, err error) {
	return s.stream.Write(p)
}

func (s *QuicStream) Close() error {
	return s.stream.Close()
}

func (s *QuicStream) Flush() error {
	// quic-go handles flushing internally
	return nil
}

func NewQuicConn(conn *quic.Conn) *QuicConn {
	return &QuicConn{conn: conn}
}

func (c *QuicConn) IsStreamed() bool {
	return true
}

// Read reads a datagram from the quic connection
// it requires datagrams to be enabled explicitly
func (c *QuicConn) Read(b []byte) (n int, err error) {
	//return 0, transport.ErrNotImplemented
	datagram, err := c.conn.ReceiveDatagram(context.Background())
	if err != nil {
		return 0, err
	}
	copy(b, datagram)
	return len(datagram), nil
}

// Write writes a datagram to the quic connection
// it requires datagrams to be enabled explicitly
func (c *QuicConn) Write(b []byte) (n int, err error) {
	//return 0, transport.ErrNotImplemented
	err = c.conn.SendDatagram(b)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *QuicConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	stream, err := c.conn.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	/*_, err = stream.Read([]byte{0})
	if err != nil {
		return nil, err
	}*/
	return &QuicStream{stream: stream}, nil
}

func (c *QuicConn) NewStream(ctx context.Context) (transport.Stream, error) {
	stream, err := c.conn.OpenStream()
	if err != nil {
		return nil, err
	}
	/*_, err = stream.Write([]byte{0})
	if err != nil {
		return nil, err
	}*/
	return &QuicStream{stream: stream}, nil
}

func (c *QuicConn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

func (c *QuicConn) RemoteAddr() net.Addr {
	return c.conn.RemoteAddr()
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

func (c *QuicConn) Close() error {
	return c.conn.CloseWithError(0, "normal closure")
}
