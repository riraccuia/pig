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

package tlsicmp

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/transport"
	"github.com/riraccuia/pig/pkg/transport/icmp"
)

func GetClientFromConn(ctx context.Context, conn net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config) (transport.Conn, error) {
	tlsConn, err := newConn(conn, tlsConfig.Clone(), false)
	if err != nil {
		fmt.Println("failed to create TLS connection", err)
		return nil, err
	}
	return tlsConn, nil
}

func GetListenerFromConn(ctx context.Context, co net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config) (transport.Listener, error) {
	listener := ice.NewListenerConn(co, func(conn net.Conn) (net.Conn, error) {
		return newConn(conn, tlsConfig.Clone(), true)
	})
	return listener, nil
}

// GetClientDialFunc returns a function that creates client connections based on config.
func GetClientDialFunc(logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config, bindAdapter string) func(ctx context.Context) (transport.Conn, error) {
	icmpDialer := icmp.GetClientDialFunc(logger, config, bindAdapter)

	return func(ctx context.Context) (transport.Conn, error) {
		// Get underlying ICMP connection
		icmpConn, err := icmpDialer(ctx)
		if err != nil {
			return nil, err
		}

		// Wrap with TLS
		tlsConn, err := newConn(icmpConn, tlsConfig.Clone(), false)
		if err != nil {
			logger.Errorf("failed to create TLS connection: %v", err)
			icmpConn.Close()
			return nil, err
		}

		return tlsConn, nil
	}
}

// GetServerListenFunc returns a function that creates server listeners based on config.
func GetServerListenFunc(logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config, bindAdapter string) func(ctx context.Context) (transport.Listener, error) {
	icmpListenFunc := icmp.GetServerListenFunc(logger, config, bindAdapter)

	return func(ctx context.Context) (transport.Listener, error) {
		// Create underlying ICMP listener
		icmpListener, err := icmpListenFunc(ctx)
		if err != nil {
			return nil, err
		}

		// Wrap with TLS
		return newListener(icmpListener, tlsConfig.Clone()), nil
	}
}
