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

package quicgo

import (
	"context"
	"net"
	"sync"

	"github.com/quic-go/quic-go"
)

type QuicListener struct {
	listener  *quic.Listener
	closeOnce sync.Once
}

func NewQuicTransport(listener *quic.Listener) *QuicListener {
	return &QuicListener{listener: listener}
}

func (t *QuicListener) Addr() net.Addr {
	if t.listener == nil {
		return nil
	}
	return t.listener.Addr()
}

func (t *QuicListener) Accept() (net.Conn, error) {
	conn, err := t.listener.Accept(context.Background())
	if err != nil {
		return nil, err
	}
	return NewQuicConn(conn), nil
}

func (t *QuicListener) Close() error {
	t.closeOnce.Do(func() {
		if t.listener == nil {
			return
		}
		t.listener.Close()
		t.listener = nil
	})
	return nil
}
