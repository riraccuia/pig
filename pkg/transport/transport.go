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

package transport

import (
	"context"
	"errors"
	"io"
	"net"
	"time"
)

var ErrNotImplemented = errors.New("not implemented")

type Stream interface {
	io.ReadWriteCloser
	Flush() error
}

type Listener interface {
	Accept() (net.Conn, error)
	Close() error
}

type Dialer interface {
	Dial(ctx context.Context, network string, address string, config any) (Conn, error)
}

type Conn interface {
	IsStreamed() bool
	Read(b []byte) (n int, err error)
	Write(b []byte) (n int, err error)
	Close() error
	AcceptStream(ctx context.Context) (Stream, error)
	NewStream(ctx context.Context) (Stream, error)
	LocalAddr() net.Addr
	RemoteAddr() net.Addr
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}
