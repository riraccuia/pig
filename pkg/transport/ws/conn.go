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
	"crypto/tls"
	"fmt"
	"net"
	"net/http"

	"github.com/coder/websocket"
	"github.com/riraccuia/pig/pkg/transport"
)

// WSConn wraps a websocket connection to implement the transport.Conn interface.
type WSConn struct {
	net.Conn
	localAddr  net.Addr
	remoteAddr net.Addr
}

func (t *WSConn) LocalAddr() net.Addr {
	if t.localAddr == nil {
		return t.Conn.LocalAddr()
	}
	return t.localAddr
}

func (t *WSConn) RemoteAddr() net.Addr {
	if t.remoteAddr == nil {
		return t.Conn.RemoteAddr()
	}
	return t.remoteAddr
}

func (t *WSConn) IsStreamed() bool {
	return false
}

func (t *WSConn) Flush() error {
	// WebSocket messages are sent immediately, no need for explicit flushing
	return nil
}

func (t *WSConn) AcceptStream(ctx context.Context) (transport.Stream, error) {
	return t, transport.ErrNotImplemented
}

func (t *WSConn) NewStream(ctx context.Context) (transport.Stream, error) {
	return t, transport.ErrNotImplemented
}

func DialConn(ctx context.Context, conn net.Conn, address string, tlsConfig *tls.Config) (transport.Conn, error) {
	scheme := "ws"
	if tlsConfig != nil {
		scheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s", scheme, address)

	var httpClient *http.Client
	if tlsConfig != nil {
		httpClient = NewHTTPSClient(conn, tlsConfig)
	}

	if httpClient == nil {
		httpClient = NewHTTPClient(conn)
	}

	options := &websocket.DialOptions{
		HTTPClient: httpClient,
	}

	wsConn, _, err := websocket.Dial(ctx, wsURL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to dial websocket: %w", err)
	}

	remoteAddr, _ := net.ResolveTCPAddr("tcp", address)

	netConn := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)
	return &WSConn{
		Conn:       netConn,
		localAddr:  conn.LocalAddr(),
		remoteAddr: remoteAddr, //conn.RemoteAddr(),
	}, nil
}

func Dial(ctx context.Context, address string, tlsConfig *tls.Config) (transport.Conn, error) {
	scheme := "ws"
	if tlsConfig != nil {
		scheme = "wss"
	}
	wsURL := fmt.Sprintf("%s://%s", scheme, address)

	httpClient := &http.Client{}
	if tlsConfig != nil {
		httpClient.Transport = &http.Transport{
			TLSClientConfig: tlsConfig,
		}
	}

	options := &websocket.DialOptions{
		HTTPClient: httpClient,
	}

	wsConn, _, err := websocket.Dial(ctx, wsURL, options)
	if err != nil {
		return nil, fmt.Errorf("failed to dial websocket: %w", err)
	}

	remoteAddr, _ := net.ResolveTCPAddr("tcp", address)

	netConn := websocket.NetConn(context.Background(), wsConn, websocket.MessageBinary)
	return &WSConn{
		Conn:       netConn,
		remoteAddr: remoteAddr,
	}, nil
}
