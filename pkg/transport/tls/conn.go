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

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/transport"
)

type TLSConn struct {
	*tls.Conn
}

func (c TLSConn) String() string {
	tlsState := c.ConnectionState()
	if !tlsState.HandshakeComplete {
		return fmt.Sprintf("proto=%s | handshake not completed", config.TransportTLS)
	}
	return fmt.Sprintf("proto=%s | tls=%s,cipher=%s,curve=%s",
		config.TransportTLS,
		tls.VersionName(tlsState.Version),
		tls.CipherSuiteName(tlsState.CipherSuite),
		tlsState.CurveID.String(),
	)
}

func (t *TLSConn) IsStreamed() bool {
	return false
}

func (t *TLSConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	// TLS connections are already streams
	return nil, transport.ErrNotImplemented
}

func (t *TLSConn) NewStream(ctx context.Context) (transport.Stream, error) {
	// TLS connections are already streams
	return nil, transport.ErrNotImplemented
}

// Implement Stream interface methods.
func (t *TLSConn) Flush() {
	// TLS connections don't need explicit flushing
}
