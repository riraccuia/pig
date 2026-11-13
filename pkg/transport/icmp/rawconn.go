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

//go:build !windows

package icmp

import (
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
)

func (l *sharedListener) setupRawConn(_ *net.Interface) error {
	ip4Conn, err := ipv4.NewRawConn(l.conn.IPConn)
	if err != nil {
		return fmt.Errorf("failed to create raw connection: %w", err)
	}
	if err := ip4Conn.SetWriteBuffer(defaultBufferSize); err != nil {
		ip4Conn.Close()
		return fmt.Errorf("failed to set write buffer: %w", err)
	}
	if err := ip4Conn.SetReadBuffer(defaultBufferSize); err != nil {
		ip4Conn.Close()
		return fmt.Errorf("failed to set read buffer: %w", err)
	}
	l.ip4Conn = ip4Conn
	return nil
}
