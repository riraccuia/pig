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

type DeadLiner interface {
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
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

// AtomicPacketConn may be implemented by a Conn that requires one IP packet
// per Write (e.g. WireGuard). Outbound batching still accumulates packets, but
// the flush path splits the batch on IP total length before writing.
type AtomicPacketConn interface {
	AtomicPacketWrites() bool
}

func GetUDPNetworkString(ipAddr net.IP) string {
	r := "udp"
	switch {
	case ipAddr == nil:
	case ipAddr.To4() == nil:
		r = "udp6"
	default:
		r = "udp4"
	}
	return r
}

func GetTCPNetworkString(ipAddr net.IP) string {
	r := "tcp"
	switch {
	case ipAddr == nil:
	case ipAddr.To4() == nil:
		r = "tcp6"
	default:
		r = "tcp4"
	}
	return r
}
