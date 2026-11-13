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
	"time"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/transport"
)

// conn implements transport.Conn and net.Conn by wrapping an ICMP connection with TLS.
type conn struct {
	*tls.Conn
	icmp net.Conn
}

// newConn creates a new TLS-over-ICMP connection.
func newConn(icmpConn net.Conn, tlsConfig *tls.Config, isServer bool) (*conn, error) {
	icmpConn.SetReadDeadline(time.Now().Add(time.Second * 5))
	defer icmpConn.SetReadDeadline(time.Time{})

	c := &conn{icmp: icmpConn}
	// Create TLS connection using our conn as the underlying transport
	switch isServer {
	case false:
		c.Conn = tls.Client(icmpConn, tlsConfig)
	case true:
		c.Conn = tls.Server(icmpConn, tlsConfig)
	}

	// Perform TLS handshake
	if err := c.Handshake(); err != nil {
		icmpConn.Close()
		return nil, err
	}

	return c, nil
}

func (c conn) String() string {
	tlsState := c.ConnectionState()
	if !tlsState.HandshakeComplete {
		return fmt.Sprintf("proto=%s | handshake not completed", config.TransportTLSICMP)
	}
	return fmt.Sprintf("proto=%s | tls=%s,cipher=%s,curve=%s",
		config.TransportTLSICMP,
		tls.VersionName(tlsState.Version),
		tls.CipherSuiteName(tlsState.CipherSuite),
		tlsState.CurveID.String(),
	)
}

// IsStreamed implements transport.Conn.
func (c *conn) IsStreamed() bool {
	return false
}

// AcceptStream implements transport.Conn.
func (c *conn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

// NewStream implements transport.Conn.
func (c *conn) NewStream(ctx context.Context) (transport.Stream, error) {
	return nil, transport.ErrNotImplemented
}

// Close waits for the underlying ICMP conn to finish delivering outbound data before TLS is closed.
func (c *conn) Close() error {
	if w, ok := c.icmp.(interface{ WaitPeerAcked() }); ok {
		w.WaitPeerAcked()
	}
	return c.Conn.Close()
}
