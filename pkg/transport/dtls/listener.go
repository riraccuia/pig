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
	"fmt"
	"net"

	"github.com/pion/dtls/v3"
	"github.com/riraccuia/pig/pkg/transport"
)

// DTLSListener wraps a DTLS listener to implement the transport.Listener interface.
type DTLSListener struct {
	net.Listener
}

// NewDTLSListener creates a new DTLS listener wrapper.
func NewDTLSListener(listener net.Listener) *DTLSListener {
	return &DTLSListener{Listener: listener}
}

// Implement transport.Listener interface methods.
func (l *DTLSListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	dtlsConn, ok := conn.(*dtls.Conn)
	if !ok {
		return nil, fmt.Errorf("accepted connection is not a DTLS connection")
	}
	return NewDTLSConn(dtlsConn), nil
}

// Listen creates a DTLS listener on the given address.
func Listen(networkstr string, laddr *net.UDPAddr, dtlsOpts ...dtls.ServerOption) (transport.Listener, error) {
	listener, err := dtls.ListenWithOptions(networkstr, laddr, dtlsOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create DTLS listener: %w", err)
	}

	return NewDTLSListener(listener), nil
}
