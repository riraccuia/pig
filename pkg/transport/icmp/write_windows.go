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

	"golang.org/x/net/ipv4"
)

// WriteTo writes an IPv4+ICMP datagram through the IPConn.
//
// ipv4.NewRawConn enables IP_HDRINCL on the socket, so Windows expects a full
// IPv4 header before the ICMP payload. ipv4.RawConn.WriteTo (sendmsg) is not
// implemented on Windows, so we marshal the header ourselves and WriteToIP.
func (l *sharedListener) WriteTo(header *ipv4.Header, p []byte, _ *ipv4.ControlMessage) error {
	if header.Src == nil && l.localAddr != nil {
		header.Src = l.localAddr.IP.To4()
	}
	wh, err := header.Marshal()
	if err != nil {
		return err
	}
	need := len(wh) + len(p)
	buf := l.getBuffer()
	defer l.clearMemory(buf)
	if need > len(buf) {
		return fmt.Errorf("icmp write exceeds buffer: need %d have %d", need, len(buf))
	}
	copy(buf, wh)
	copy(buf[len(wh):], p)
	_, err = l.conn.WriteToIP(buf[:need], &net.IPAddr{IP: header.Dst})
	return err
}
