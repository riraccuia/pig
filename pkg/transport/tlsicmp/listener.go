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
	"crypto/tls"
	"net"

	"github.com/riraccuia/pig/pkg/transport"
)

// listener implements transport.Listener by wrapping an ICMP listener with TLS.
type listener struct {
	icmpListener transport.Listener
	tlsConfig    *tls.Config
}

// newListener creates a new TLS-over-ICMP listener.
func newListener(icmpListener transport.Listener, tlsConfig *tls.Config) *listener {
	return &listener{
		icmpListener: icmpListener,
		tlsConfig:    tlsConfig,
	}
}

// Accept implements transport.Listener.
func (l *listener) Accept() (net.Conn, error) {
	// Accept underlying ICMP connection
	icmpConn, err := l.icmpListener.Accept()
	if err != nil {
		return nil, err
	}

	// Wrap with TLS
	tlsConn, err := newConn(icmpConn, l.tlsConfig, true)
	if err != nil {
		icmpConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// Close implements transport.Listener.
func (l *listener) Close() error {
	return l.icmpListener.Close()
}
