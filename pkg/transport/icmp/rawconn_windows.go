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

package icmp

import (
	"fmt"
	"net"
)

// setupRawConn prepares the ICMP socket for Windows.
//
// Do not call ipv4.NewRawConn: it enables IP_HDRINCL. Keep the default so
// Winsock builds the IPv4 header and we send ICMP payloads only.
func (l *sharedListener) setupRawConn(_ *net.Interface) error {
	if err := l.conn.SetWriteBuffer(defaultBufferSize); err != nil {
		return fmt.Errorf("failed to set write buffer: %w", err)
	}
	if err := l.conn.SetReadBuffer(defaultBufferSize); err != nil {
		return fmt.Errorf("failed to set read buffer: %w", err)
	}
	return nil
}
