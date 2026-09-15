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
	"crypto/tls"
	"fmt"
	"net"
)

type TLSListener struct {
	listener net.Listener
}

func NewTLSListener(listener net.Listener) *TLSListener {
	return &TLSListener{listener: listener}
}

func (t *TLSListener) Accept() (net.Conn, error) {
	conn, err := t.listener.Accept()
	if err != nil {
		return nil, err
	}
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return nil, fmt.Errorf("accepted connection is not a TLS connection")
	}
	return NewTLSConn(tlsConn), nil
}

func (t *TLSListener) Close() error {
	return t.listener.Close()
}
