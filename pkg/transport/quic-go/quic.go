package quicgo

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime"

	"github.com/quic-go/quic-go"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice/conn"
	"github.com/riraccuia/pig/pkg/transport"
)

func GetClientDialFunc(ctx context.Context, logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config) func() (transport.Conn, error) {
	return dialFuncWithSrcPort(ctx, logger, config.Target.Address, config.Target.SrcPort, config.Target.Port, tlsConfig)
}

func GetServerListenFunc(ctx context.Context, logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config) func() (transport.Listener, error) {
	return func() (transport.Listener, error) {
		var (
			udpConn      *net.UDPConn
			listenerAddr = &net.UDPAddr{IP: nil, Port: config.Target.Port}
			err          error
		)
		udpConn, err = conn.ListenUDP("udp", listenerAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on endpoint: %w", err)
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
				EnableDatagrams:    true,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on endpoint: %w", err)
		}
		return NewQuicTransport(ctx, listener), nil
	}
}

func GetClientFromConn(ctx context.Context, conn net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config) (transport.Conn, error) {
	if tlsConfig == nil {
		return nil, errors.New("quic: tls.Config not set")
	}
	tr := &quic.Transport{
		Conn: conn.(net.PacketConn),
	}
	qConn, err := tr.Dial(
		ctx,
		conn.RemoteAddr(),
		tlsConfig.Clone(),
		&quic.Config{
			EnableDatagrams: true,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
	}
	return NewQuicConn(qConn), nil
}

func GetListenerFromConn(ctx context.Context, co net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config) (transport.Listener, error) {
	if tlsConfig == nil {
		return nil, errors.New("quic: tls.Config not set")
	}
	maxStreams := int64(config.StreamCount)
	if maxStreams <= 0 {
		maxStreams = int64(runtime.NumCPU())
	}
	listener, err := quic.Listen(co.(net.PacketConn), tlsConfig.Clone(), &quic.Config{
		EnableDatagrams:    true,
		MaxIncomingStreams: maxStreams,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to listen using QUIC on endpoint: %w", err)
	}
	return NewQuicTransport(ctx, listener), nil
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

func dialFuncWithSrcPort(ctx context.Context, logger common.Logger, address string, srcPort, dstPort int, tlsConfig *tls.Config) func() (transport.Conn, error) {
	return func() (transport.Conn, error) {
		var (
			udpConn *net.UDPConn
			udpAddr *net.UDPAddr
			err     error
		)
		udpConn, err = conn.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: srcPort})
		if err != nil {
			return nil, err
		}
		udpAddr, err = net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", address, dstPort))
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
			&quic.Config{
				EnableDatagrams: true,
			},
		)
		if err != nil {
			return nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
		}
		return NewQuicConn(conn), nil
	}
}
