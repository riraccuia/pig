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

package ws

import (
	"context"
	"net"
	"net/http"
	"sync"

	"crypto/tls"

	"github.com/coder/websocket"
)

// WSListener implements transport.Listener for WebSocket connections.
type WSListener struct {
	server    *http.Server
	connChan  chan *WSConn
	closeOnce sync.Once
}

// NewWSListener creates a new WebSocket transport.
func NewWSListener() *WSListener {
	return &WSListener{
		connChan: make(chan *WSConn),
	}
}

func (t *WSListener) Accept() (net.Conn, error) {
	conn, ok := <-t.connChan
	if !ok {
		return nil, net.ErrClosed
	}
	return conn, nil
}

func (t *WSListener) Close() error {
	t.closeOnce.Do(func() {
		if t.server == nil {
			return
		}
		close(t.connChan)
		// this will close the listener but not the websocket connection
		t.server.Close()
		t.server = nil
	})
	return nil
}

func (t *WSListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	wsConn, err := websocket.Accept(w, r, &websocket.AcceptOptions{})
	if err != nil {
		return
	}

	netConn := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)
	conn := &WSConn{Conn: netConn}

	select {
	case t.connChan <- conn:
	default:
		netConn.Close()
	}
}

// Listen starts the WebSocket server on the given address.
func (t *WSListener) ListenWithListener(l net.Listener, tlsConfig *tls.Config) error {
	t.server = &http.Server{
		Handler:   t,
		TLSConfig: tlsConfig,
		ConnState: func(conn net.Conn, newState http.ConnState) {
			if newState != http.StateClosed {
				return
			}
			// This was a half-open connection, because it never got hijacked
			// so we need to close the listener to free the resources
			t.Close()
		},
	}

	return t.server.Serve(tls.NewListener(l, tlsConfig))
}

// Listen starts the WebSocket server on the given address.
func (t *WSListener) Listen(network, address string, tlsConfig *tls.Config) error {
	ln, err := net.Listen(network, address)
	if err != nil {
		return err
	}

	t.server = &http.Server{
		Addr:      address,
		Handler:   t,
		TLSConfig: tlsConfig,
	}

	if tlsConfig != nil {
		return t.server.ServeTLS(ln, "", "")
	}
	return t.server.Serve(ln)
}
