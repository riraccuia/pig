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

import "net"

// ReadMsgIP reads an ICMP datagram from the IPPROTO_ICMP socket.
//
// Uses ReadFromIP (WSARecvFrom) instead of ReadMsgIP (WSARecvMsg). oob is
// ignored; oobn and flags are always 0.
func (l *sharedListener) ReadMsgIP(b, _ []byte) (n, oobn, flags int, addr *net.IPAddr, err error) {
	n, addr, err = l.conn.ReadFromIP(b)
	return n, 0, 0, addr, err
}
