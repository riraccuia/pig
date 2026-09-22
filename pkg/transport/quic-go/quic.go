// Copyright 2026 Riccardo Raccuia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package quicgo

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"runtime"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/transport"
)

func GetClientDialFunc(logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config) func(ctx context.Context) (transport.Conn, error) {
	return dialFuncWithSrcPort(logger, config.Connect.Address, config.Connect.SrcPort, config.Connect.Port, tlsConfig)
}

func GetServerListenFunc(logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config) func(ctx context.Context) (transport.Listener, error) {
	return func(ctx context.Context) (transport.Listener, error) {
		var (
			udpConn      *net.UDPConn
			listenerAddr = &net.UDPAddr{IP: net.ParseIP(config.Listen.Address), Port: config.Listen.Port}
			err          error
		)
		udpConn, err = network.ListenUDP("udp", listenerAddr)
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
				MaxIdleTimeout:     time.Minute,
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
			MaxIdleTimeout:  time.Minute,
			KeepAlivePeriod: time.Second * 30,
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

func dialFuncWithSrcPort(logger common.Logger, address string, srcPort, dstPort int, tlsConfig *tls.Config) func(ctx context.Context) (transport.Conn, error) {
	return func(ctx context.Context) (transport.Conn, error) {
		var (
			udpConn *net.UDPConn
			udpAddr *net.UDPAddr
			err     error
		)
		udpConn, err = network.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: srcPort})
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
