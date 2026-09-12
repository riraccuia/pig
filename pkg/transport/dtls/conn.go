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
	"fmt"
	"net"

	"github.com/pion/dtls/v3"
	"github.com/riraccuia/pig/pkg/transport"
)

// DTLSConn wraps a DTLS connection to implement the transport.Conn interface.
type DTLSConn struct {
	*dtls.Conn
}

// NewDTLSConn creates a new DTLS connection wrapper.
func NewDTLSConn(dtlsConn *dtls.Conn) *DTLSConn {
	return &DTLSConn{Conn: dtlsConn}
}

// Implement transport.Conn interface methods.
func (c *DTLSConn) IsStreamed() bool {
	return false
}

func (c *DTLSConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *DTLSConn) NewStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

func (c *DTLSConn) Flush() {
	// DTLS connections don't need explicit flushing.
}

// Dial establishes a DTLS connection to the given address.
func Dial(ctx context.Context, address string, dtlsConfig *dtls.Config) (transport.Conn, error) {
	// Parse the address
	raddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve address: %w", err)
	}

	conn, err := dtls.Dial("udp", raddr, dtlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to establish DTLS connection: %w", err)
	}

	return NewDTLSConn(conn), nil
}

// DialConn establishes a DTLS connection using an existing UDP connection.
func DialConn(ctx context.Context, conn net.Conn, address string, dtlsConfig *dtls.Config) (transport.Conn, error) {
	// Use the existing connection to establish DTLS
	dtlsConn, err := dtls.Client(conn.(net.PacketConn), conn.RemoteAddr(), dtlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to establish DTLS connection: %w", err)
	}

	return NewDTLSConn(dtlsConn), nil
}
