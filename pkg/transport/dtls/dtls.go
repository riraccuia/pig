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

package dtls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/pion/dtls/v3"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/transport"
)

// GetClientFromConn creates a DTLS client connection from an existing connection.
func GetClientFromConn(ctx context.Context, conn net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config, mtu int) (transport.Conn, error) {
	opts := getClientOptions(tlsConfig, mtu)
	packetConn := network.NewPacketConn(conn.(*net.UDPConn))
	dtlsConn, err := DialConn(ctx, packetConn, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to establish DTLS connection: %w", err)
	}
	idleTimeout := time.Duration(config.IdleTimeout) * time.Second
	ctx, cancel := context.WithTimeout(ctx, idleTimeout)
	defer cancel()
	err = dtlsConn.HandshakeContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to handshake: %w", err)
	}
	return NewDTLSConn(dtlsConn), nil
}

// GetListenerFromConn creates a DTLS listener from an existing connection.
func GetListenerFromConn(ctx context.Context, co net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config, mtu int) (transport.Listener, error) {
	opts := getServerOptions(tlsConfig, mtu)
	packetConn := network.NewPacketConn(co.(*net.UDPConn))
	listenerConn := ice.NewPacketListenerConn(packetConn, nil)
	dtlsListener, err := dtls.NewListenerWithOptions(listenerConn, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create DTLS listener: %w", err)
	}
	return NewDTLSListener(dtlsListener), nil
}

// GetClientDialFunc returns a function that creates DTLS client connections.
func GetClientDialFunc(logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config, mtu int) func(ctx context.Context) (transport.Conn, error) {
	return func(ctx context.Context) (transport.Conn, error) {
		udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(config.Connect.Address, strconv.Itoa(config.Connect.Port)))
		if err != nil {
			return nil, fmt.Errorf("failed to resolve address: %w", err)
		}
		networkStr := transport.GetUDPNetworkString(udpAddr.IP)

		opts := getClientOptions(tlsConfig, mtu)
		dtlsConn, err := Dial(
			ctx,
			networkStr,
			udpAddr,
			opts...,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to establish DTLS connection: %w", err)
		}
		idleTimeout := time.Duration(config.IdleTimeout) * time.Second
		ctx, cancel := context.WithTimeout(ctx, idleTimeout)
		defer cancel()
		err = dtlsConn.HandshakeContext(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to handshake: %w", err)
		}
		return NewDTLSConn(dtlsConn), nil
	}
}

// GetServerListenFunc returns a function that creates DTLS server listeners.
func GetServerListenFunc(logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config, mtu int) func(ctx context.Context) (transport.Listener, error) {
	return func(ctx context.Context) (transport.Listener, error) {
		opts := getServerOptions(tlsConfig, mtu)

		udpAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(config.Listen.Address, strconv.Itoa(config.Listen.Port)))
		if err != nil {
			return nil, fmt.Errorf("failed to resolve address: %w", err)
		}
		networkStr := transport.GetUDPNetworkString(udpAddr.IP)

		listener, err := Listen(
			networkStr,
			udpAddr,
			opts...,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create DTLS listener: %w", err)
		}
		return listener, nil
	}
}
