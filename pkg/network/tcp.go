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

package network

import (
	"context"
	"net"
	"time"
)

// DialTCP uses a net.Dialer to dial a TCP connection and sets the SO_REUSEADDR and TCP_NODELAY options.
func DialTCP(network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	dialer := NewDialer(5 * time.Second)
	return dialTCP(context.Background(), dialer, network, laddr, raddr)
}

func DialTCPContext(ctx context.Context, network string, laddr, raddr *net.TCPAddr) (*net.TCPConn, error) {
	dialer := NewDialer(5 * time.Second)
	return dialTCP(ctx, dialer, network, laddr, raddr)
}
