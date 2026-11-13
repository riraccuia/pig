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

// ReadMsgIP reads the next IPv4 ICMP datagram from the SIO_RCVALL socket.
// Non-ICMP traffic is skipped. oob is ignored; oobn and flags are always 0.
func (l *sharedListener) ReadMsgIP(b, _ []byte) (n, oobn, flags int, addr *net.IPAddr, err error) {
	if l.recvConn == nil {
		return 0, 0, 0, nil, fmt.Errorf("windows ICMP receive socket not configured")
	}
	for {
		n, addr, err = l.recvConn.ReadFromIP(b)
		if err != nil {
			return 0, 0, 0, nil, err
		}
		// IPv4 header protocol field
		if n >= 20 && b[9] == protocolICMP {
			return n, 0, 0, addr, nil
		}
	}
}
