package network

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"slices"
	"syscall"
	"time"

	"golang.org/x/net/ipv6"
)

const (
	// IPv6 minimum link MTU per RFC 8200; must not reduce below this (RFC 8201).
	ipv6MinimumMTU = 1280
	// ICMPv6 Echo header: Type(1) Code(1) Checksum(2) Identifier(2) Sequence(2) = 8 bytes.
	icmpv6EchoHeaderLen = 8
	// PTB: Type(1) Code(1) Checksum(2) MTU(4) = 8; then invoking packet.
	icmpv6PTBMTUOffset = 4
	icmpv6PTBInvoking  = 8
	// Time to wait for Echo Reply or Packet Too Big after sending a probe.
	probeTimeout = time.Second * 3
	maxProbes    = 64
)

var (
	errNotIPv6 = errors.New("destination is not an IPv6 address")
	errNoRoute = errors.New("no route to destination")
	errNoReply = errors.New("no reply within timeout")
)

// PathMTUDiscovery6 discovers the path MTU to dst using IPv6 Path MTU Discovery (RFC 8201).
// It sends ICMPv6 Echo Request probes and, on ICMPv6 Packet Too Big (RFC 4443),
// reduces the probe size to the reported MTU (never below 1280) and retries.
// Returns the usable MTU in octets, or an error if discovery fails.
func PathMTUDiscovery6(dst net.IP) (int, error) {
	if dst.To4() != nil {
		return 0, errNotIPv6
	}

	dst6 := dst.To16()

	_, iface, err := sourceAddrForDst(dst6)
	if err != nil {
		return 0, errNoRoute
	}

	mtu := iface.MTU
	if iface.MTU < ipv6MinimumMTU {
		mtu = 1500
	}

	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				setSockoptIPV6DontFrag(fd)
			})
		},
	}

	conn, err := lc.ListenPacket(context.Background(), "ip6:58", "::")
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	destAddr := &net.IPAddr{IP: dst6}
	pmtu := mtu
	id := uint16(1)
	seq := uint16(0)

	for i := 0; i < maxProbes; i++ {
		pkt := NewICMPv6EchoRequest(id, seq, pmtu-ipv6.HeaderLen)

		_ = conn.SetReadDeadline(time.Now().Add(probeTimeout))
		// Raw socket adds IPv6 header; send only ICMPv6 payload and header as out-of-band data.
		//if _, _, err := conn.WriteMsgIP(pkt[pkt.PayloadOffset():], pkt[:ipv6.HeaderLen], destAddr); err != nil {
		if _, err := conn.WriteTo(pkt, destAddr); err != nil {
			return 0, err
		}
		seq++

		payload := make([]byte, ipv6MinimumMTU-ipv6.HeaderLen)
		n, _, err := conn.ReadFrom(payload) //ReadMsgIP(payload, nil)
		if err != nil {
			if os.IsTimeout(err) {
				// No PTB and no Echo Reply
				return 0, errNoReply
			}
			return 0, err
		}
		payload = payload[:n]

		msgType := payload[0]
		msgCode := payload[1]

		switch msgType {
		case uint8(ipv6.ICMPTypeEchoReply):
			if msgCode != 0 || len(payload) < icmpv6EchoHeaderLen {
				continue
			}
			rxID := binary.BigEndian.Uint16(payload[4:6])
			rxSeq := binary.BigEndian.Uint16(payload[6:8])
			if rxID == id && rxSeq == seq-1 {
				return pmtu, nil
			}
		case uint8(ipv6.ICMPTypePacketTooBig):
			if msgCode != 0 || len(payload) < 8 {
				continue
			}
			reportedMTU := binary.BigEndian.Uint32(payload[icmpv6PTBMTUOffset:8])
			// Validate PTB applies to our probe: invoking packet's destination must be dst (RFC 8201).
			if len(payload) < icmpv6PTBInvoking+40 {
				// not enough data to check
				// retry
				continue
			}
			invoking := payload[icmpv6PTBInvoking:]
			if len(invoking) < ipv6.HeaderLen {
				// not enough data to check
				// retry
				continue
			}
			if !IPv6Packet(invoking).DestinationIP().Equal(dst6) {
				// not our packet
				// retry
				continue
			}
			// Must not reduce below IPv6 minimum link MTU (RFC 8201).
			if reportedMTU < ipv6MinimumMTU {
				continue
			}
			// Must not increase PMTU based on PTB (RFC 8201).
			if int(reportedMTU) < pmtu {
				pmtu = int(reportedMTU)
			}
			continue
		}
	}
	// Fallback: return current (reduced) pmtu after many PTBs.
	return pmtu, nil
}

// sourceAddrForDst returns a source IPv6 address that has a route to dst
// and the interface mtu for that route
func sourceAddrForDst(dst net.IP) (net.IP, *net.Interface, error) {
	c, err := net.Dial("udp6", net.JoinHostPort(dst.String(), "53"))
	if err != nil {
		return nil, nil, err
	}
	_ = c.Close()
	la := c.LocalAddr()
	if la == nil {
		return nil, nil, errNoRoute
	}
	addr, ok := la.(*net.UDPAddr)
	if !ok || addr.IP == nil {
		return nil, nil, errNoRoute
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	var bestIface *net.Interface
	for _, iface := range interfaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		if slices.ContainsFunc(addrs, func(a net.Addr) bool {
			return a.(*net.IPNet).IP.Equal(addr.IP)
		}) {
			bestIface = &iface
			break
		}
	}

	return addr.IP.To16(), bestIface, nil
}
