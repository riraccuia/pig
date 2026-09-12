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
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// sendEchoMessage sends an ICMP echo request with the given data.
func (c *Conn) sendEchoMessage(data []byte) error {
	seq := c.nextIcmpSeq.Load()
	c.nextIcmpSeq.Add(1)

	icmpType := ipv4.ICMPTypeEcho
	if c.listener.isServer {
		icmpType = ipv4.ICMPTypeEchoReply
	}

	msg := &icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   int(c.icmpID),
			Seq:  int(seq),
			Data: data,
		},
	}

	return c.listener.writePacket(c.remoteAddr.IP.To4(), msg)
}

func (c *Conn) sendCloseMessage() error {
	c.listener.logger.Infof("Sending close message to %s", c.remoteAddr.IP.To4())

	seq := c.nextIcmpSeq.Load()
	c.nextIcmpSeq.Add(1)

	icmpType := ipv4.ICMPTypeEcho
	if c.listener.isServer {
		icmpType = ipv4.ICMPTypeEchoReply
	}

	msg := &icmp.Message{
		Type: icmpType,
		Code: 255,
		Body: &icmp.Echo{
			ID:   int(c.icmpID),
			Seq:  int(seq),
			Data: []byte{},
		},
	}

	return c.listener.writePacket(c.remoteAddr.IP.To4(), msg)
}
