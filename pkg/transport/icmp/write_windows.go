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
	"net"

	"golang.org/x/net/ipv4"
)

// WriteTo writes an ICMP payload through the IPConn.
//
// ipv4.RawConn.WriteTo (sendmsg) is not implemented on Windows. With IP_HDRINCL
// left off (see setupRawConn), Winsock builds the IPv4 header; only the ICMP
// message is written. The header argument is used for the destination address.
func (l *sharedListener) WriteTo(header *ipv4.Header, p []byte, _ *ipv4.ControlMessage) error {
	_, err := l.conn.WriteToIP(p, &net.IPAddr{IP: header.Dst})
	return err
}
