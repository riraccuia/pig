package quicgo

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/transport"
)

type QuicStream struct {
	stream quic.Stream
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

func (s *QuicStream) Flush() {
	// quic-go handles flushing internally
}

type QuicConn struct {
	conn quic.Connection
}

func NewQuicConn(conn quic.Connection) *QuicConn {
	return &QuicConn{conn: conn}
}

func (c *QuicConn) IsStreamed() bool {
	return true
}

func (c *QuicConn) Read(b []byte) (n int, err error) {
	return 0, transport.ErrNotImplemented
}

func (c *QuicConn) Write(b []byte) (n int, err error) {
	return 0, transport.ErrNotImplemented
}

func (c *QuicConn) Close() error {
	return c.conn.CloseWithError(0, "normal closure")
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

type QuicTransport struct {
	listener *quic.Listener
}

func NewQuicTransport(listener *quic.Listener) *QuicTransport {
	return &QuicTransport{listener: listener}
}

func (t *QuicTransport) Accept(ctx context.Context) (transport.Conn, error) {
	conn, err := t.listener.Accept(ctx)
	if err != nil {
		return nil, err
	}
	return NewQuicConn(conn), nil
}

func (t *QuicTransport) Close() error {
	return t.listener.Close()
}

func GetClientDialFunc(ctx context.Context, config *config.Config, tlsConfig *tls.Config) func() (transport.Conn, error) {
	return dialFuncWithSrcPort(ctx, config.Target.Address, config.Target.SrcPort, config.Target.Port, tlsConfig, config)
}

func GetServerListenFunc(ctx context.Context, config *config.Config, tlsConfig *tls.Config) func() (transport.Listener, error) {
	return func() (transport.Listener, error) {
		udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: config.Target.Port})
		if err != nil {
			return nil, fmt.Errorf("failed to listen on endpoint: %w", err)
		}
		if config.ICE.Enabled {
			logger := log.NewBlockingLogger()
			logger.SetLevel(config.LogLevel)
			err := signaling.ReceivePunchRequests(ctx, signaling.GetOptionsWithLogger(logger, &config.ICE), udpConn)
			if err != nil {
				return nil, fmt.Errorf("failed to setup punch signaling channel: %w", err)
			}
		}
		maxStreams := int64(config.StreamCount)
		if maxStreams <= 0 {
			maxStreams = int64(runtime.NumCPU())
		}
		listener, err := quic.Listen(
			udpConn,
			tlsConfig.Clone(),
			&quic.Config{
				MaxIncomingStreams: maxStreams,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on endpoint: %w", err)
		}
		return NewQuicTransport(listener), nil
	}
}

func dialFuncDefault(ctx context.Context, address string, dstPort int, tlsConfig *tls.Config) func() (transport.Conn, error) {
	return func() (transport.Conn, error) {
		conn, err := quic.DialAddr(
			ctx,
			fmt.Sprintf("%s:%d", address, dstPort),
			tlsConfig.Clone(),
			&quic.Config{},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
		}
		return NewQuicConn(conn), nil
	}
}

func dialFuncWithSrcPort(ctx context.Context, address string, srcPort, dstPort int, tlsConfig *tls.Config, cfg *config.Config) func() (transport.Conn, error) {
	return func() (transport.Conn, error) {
		udpConn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: srcPort})
		if err != nil {
			return nil, err
		}
		if cfg.ICE.Enabled {
			logger := log.NewBlockingLogger()
			logger.SetLevel(cfg.LogLevel)
			err := signaling.SignalPunchRequest(ctx,
				signaling.GetOptionsWithLogger(logger, &cfg.ICE),
				address+":"+strconv.Itoa(dstPort),
				udpConn,
			)
			if err != nil {
				return nil, fmt.Errorf("failed to signal punch request: %w", err)
			}
			time.Sleep(time.Second)
		}
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", address, dstPort))
		if err != nil {
			return nil, err
		}
		if tlsConfig == nil {
			return nil, errors.New("quic: tls.Config not set")
		}
		tr := &quic.Transport{
			Conn: udpConn,
		}
		conn, err := tr.Dial(
			ctx,
			udpAddr,
			tlsConfig,
			&quic.Config{},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
		}
		return NewQuicConn(conn), nil
	}
}
