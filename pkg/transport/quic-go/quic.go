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
	"strconv"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/transport"
)

func GetClientDialFunc(logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config) func(ctx context.Context) (transport.Conn, error) {
	return dialFuncWithSrcPort(config.Connect.Address, config.Connect.SrcPort, config.Connect.Port, config.IdleTimeout, tlsConfig)
}

func GetServerListenFunc(logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config) func(ctx context.Context) (transport.Listener, error) {
	return func(ctx context.Context) (transport.Listener, error) {
		var (
			udpConn   *net.UDPConn
			localAddr *net.UDPAddr
			err       error
		)

		localAddr, err = net.ResolveUDPAddr("udp", net.JoinHostPort(config.Listen.Address, strconv.Itoa(config.Listen.Port)))
		if err != nil {
			return nil, fmt.Errorf("failed to resolve address: %w", err)
		}
		networkStr := transport.GetUDPNetworkString(localAddr.IP)

		udpConn, err = network.ListenUDP(networkStr, localAddr)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on endpoint: %w", err)
		}

		tr := &quic.Transport{
			Conn: udpConn,
		}

		quicConfig := getServerQuicConfig(config.StreamCount, config.IdleTimeout)

		listener, err := tr.Listen(tlsConfig.Clone(), quicConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to listen on endpoint: %w", err)
		}
		return NewQuicTransport(listener), nil
	}
}

func GetClientFromConn(ctx context.Context, conn net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config) (transport.Conn, error) {
	if tlsConfig == nil {
		return nil, errors.New("quic: tls.Config not set")
	}

	packetConn := network.ConnectedUdpToPacketConn(conn.(*net.UDPConn))
	tr := &quic.Transport{
		Conn: packetConn,
	}

	quicConfig := getClientQuicConfig(config.IdleTimeout)

	qConn, err := tr.Dial(
		ctx,
		conn.RemoteAddr(),
		tlsConfig.Clone(),
		quicConfig,
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
	packetConn := network.ConnectedUdpToPacketConn(co.(*net.UDPConn))
	tr := &quic.Transport{
		Conn: packetConn,
	}
	quicConfig := getServerQuicConfig(config.StreamCount, config.IdleTimeout)
	listener, err := tr.Listen(tlsConfig.Clone(), quicConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to listen using QUIC on endpoint: %w", err)
	}
	return NewQuicTransport(listener), nil
}

func dialFuncWithSrcPort(address string, srcPort, dstPort int, idleTimeoutSec int, tlsConfig *tls.Config) func(ctx context.Context) (transport.Conn, error) {
	return func(ctx context.Context) (transport.Conn, error) {
		var (
			udpConn    *net.UDPConn
			localAddr  *net.UDPAddr
			targetAddr *net.UDPAddr
			err        error
		)

		targetAddr, err = net.ResolveUDPAddr("udp", net.JoinHostPort(address, strconv.Itoa(dstPort)))
		if err != nil {
			return nil, err
		}
		networkStr := transport.GetUDPNetworkString(targetAddr.IP)

		localAddr, err = net.ResolveUDPAddr(networkStr, net.JoinHostPort("", strconv.Itoa(srcPort)))
		if err != nil {
			return nil, err
		}

		udpConn, err = network.ListenUDP(networkStr, localAddr)
		if err != nil {
			return nil, err
		}

		if tlsConfig == nil {
			return nil, errors.New("quic: tls.Config not set")
		}
		tr := &quic.Transport{
			Conn: udpConn,
		}
		quicConfig := getClientQuicConfig(idleTimeoutSec)
		conn, err := tr.Dial(
			ctx,
			targetAddr,
			tlsConfig.Clone(),
			quicConfig,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
		}
		return NewQuicConn(conn), nil
	}
}

func getTimeoutAndKeepalivePeriod(idleTimeoutSec int) (time.Duration, time.Duration) {
	if idleTimeoutSec <= 0 {
		return 0, 0
	}
	idleTimeout := time.Duration(idleTimeoutSec) * time.Second
	keepalivePeriod := idleTimeout / 2
	if keepalivePeriod < time.Second {
		keepalivePeriod = 0
	}
	return idleTimeout, keepalivePeriod
}

func getClientQuicConfig(idleTimeoutSec int) *quic.Config {
	idleTimeout, keepalivePeriod := getTimeoutAndKeepalivePeriod(idleTimeoutSec)
	return &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  idleTimeout,
		KeepAlivePeriod: keepalivePeriod,
	}
}

func getServerQuicConfig(streamCount, idleTimeoutSec int) *quic.Config {
	maxStreams := int64(streamCount)
	if maxStreams <= 0 {
		maxStreams = int64(runtime.NumCPU())
	}
	idleTimeout, _ := getTimeoutAndKeepalivePeriod(idleTimeoutSec)
	return &quic.Config{
		MaxIncomingStreams: maxStreams,
		EnableDatagrams:    true,
		MaxIdleTimeout:     idleTimeout,
	}
}
