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

	"github.com/pion/dtls/v3"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/transport"
)

// GetClientFromConn creates a DTLS client connection from an existing connection.
func GetClientFromConn(ctx context.Context, conn net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config, mtu int) (transport.Conn, error) {
	dtlsConfig := &dtls.Config{
		InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
		ServerName:         tlsConfig.ServerName,
		MTU:                mtu,
	}

	if len(tlsConfig.Certificates) > 0 {
		dtlsConfig.Certificates = []tls.Certificate{tlsConfig.Certificates[0]}
	}

	if tlsConfig.RootCAs != nil {
		dtlsConfig.RootCAs = tlsConfig.RootCAs
	}

	dtlsConn, err := DialConn(ctx, conn, conn.RemoteAddr().String(), dtlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to establish DTLS connection: %w", err)
	}
	return dtlsConn, nil
}

// GetListenerFromConn creates a DTLS listener from an existing connection.
func GetListenerFromConn(ctx context.Context, co net.Conn, config *config.TunnelConfig, tlsConfig *tls.Config, mtu int) (transport.Listener, error) {
	dtlsConfig := &dtls.Config{
		InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
		ServerName:         tlsConfig.ServerName,
		MTU:                mtu,
	}

	if len(tlsConfig.Certificates) > 0 {
		dtlsConfig.Certificates = []tls.Certificate{tlsConfig.Certificates[0]}
	}

	if tlsConfig.ClientCAs != nil {
		dtlsConfig.ClientCAs = tlsConfig.ClientCAs
	}

	listenerConn := ice.NewPacketListenerConn(co, nil)
	dtlsListener, err := dtls.NewListener(listenerConn, dtlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create DTLS listener: %w", err)
	}
	return NewDTLSListener(dtlsListener), nil
}

// GetClientDialFunc returns a function that creates DTLS client connections.
func GetClientDialFunc(logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config, mtu int) func(ctx context.Context) (transport.Conn, error) {
	return func(ctx context.Context) (transport.Conn, error) {
		dtlsConfig := &dtls.Config{
			InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
			ServerName:         tlsConfig.ServerName,
			MTU:                mtu,
		}

		if len(tlsConfig.Certificates) > 0 {
			dtlsConfig.Certificates = []tls.Certificate{tlsConfig.Certificates[0]}
		}

		if tlsConfig.RootCAs != nil {
			dtlsConfig.RootCAs = tlsConfig.RootCAs
		}

		conn, err := Dial(
			ctx,
			fmt.Sprintf("%s:%d", config.Connect.Address, config.Connect.Port),
			dtlsConfig,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to establish DTLS connection: %w", err)
		}
		return conn, nil
	}
}

// GetServerListenFunc returns a function that creates DTLS server listeners.
func GetServerListenFunc(logger common.Logger, config *config.TunnelConfig, tlsConfig *tls.Config, mtu int) func(ctx context.Context) (transport.Listener, error) {
	return func(ctx context.Context) (transport.Listener, error) {
		dtlsConfig := &dtls.Config{
			InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
			ServerName:         tlsConfig.ServerName,
			MTU:                mtu,
		}

		if len(tlsConfig.Certificates) > 0 {
			dtlsConfig.Certificates = []tls.Certificate{tlsConfig.Certificates[0]}
		}

		if tlsConfig.ClientCAs != nil {
			dtlsConfig.ClientCAs = tlsConfig.ClientCAs
		}

		listener, err := Listen(
			"udp",
			fmt.Sprintf("%s:%d", config.Listen.Address, config.Listen.Port),
			dtlsConfig,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create DTLS listener: %w", err)
		}
		return listener, nil
	}
}
