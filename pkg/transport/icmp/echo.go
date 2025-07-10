package icmp

import (
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// sendEchoMessage sends an ICMP echo request with the given data
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
