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

package tls

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/transport"
)

func GetClientFromConn(ctx context.Context, co net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config) (transport.Conn, error) {
	tlsConn := tls.Client(co, tlsConfig.Clone())
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("failed to handshake: %w", err)
	}
	return NewTLSConn(tlsConn), nil
}

func GetListenerFromConn(ctx context.Context, co net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config) (transport.Listener, error) {
	tlsConn := tls.Server(co, tlsConfig.Clone())
	return ice.NewListenerConn(NewTLSConn(tlsConn), nil), nil
}

func GetClientDialFunc(logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config) func(ctx context.Context) (transport.Conn, error) {
	return func(ctx context.Context) (transport.Conn, error) {
		addr := fmt.Sprintf("%s:%d", config.Connect.Address, config.Connect.Port)
		dialer := &net.Dialer{
			LocalAddr: &net.TCPAddr{
				Port: config.Connect.SrcPort,
			},
		}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig.Clone())
		if err != nil {
			return nil, fmt.Errorf("failed to establish TLS connection: %w", err)
		}
		return NewTLSConn(conn), nil
	}
}

func GetServerListenFunc(logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config) func(ctx context.Context) (transport.Listener, error) {
	return func(ctx context.Context) (transport.Listener, error) {
		addr := fmt.Sprintf("%s:%d", config.Listen.Address, config.Listen.Port)
		listener, err := tls.Listen("tcp", addr, tlsConfig.Clone())
		if err != nil {
			return nil, fmt.Errorf("failed to create TLS listener: %w", err)
		}
		return NewTLSListener(listener), nil
	}
}
