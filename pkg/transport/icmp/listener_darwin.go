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

	"github.com/riraccuia/pig/pkg/bpf"
)

// ipConn is a wrapper around net.IPConn that adds a BPF sniffer.
// This is required on darwin due to incoming ICMP packets being intercepted by the kernel
// and not passed to the user space, the BPF sniffer adds some overhead but allows us to
// read the packets from the kernel space.
type ipConn struct {
	*net.IPConn
	sniffer *bpf.BPFSniffer
}

func newIcmpIPConn(bindAddr *net.IPAddr, iface *net.Interface, isServer bool) (*ipConn, error) {
	conn, err := net.ListenIP("ip4:icmp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create ICMP socket: %w", err)
	}
	if !isServer {
		return &ipConn{
			IPConn: conn,
		}, nil
	}
	filter := bpf.IcmpEchoRequestFilter
	sniffer, err := bpf.NewBPFSniffer(iface.Name, filter, bpf.BPF_D_IN)
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF sniffer: %w", err)
	}
	return &ipConn{
		IPConn:  conn,
		sniffer: sniffer,
	}, nil
}

func (c *ipConn) ReadMsgIP(b []byte, oob []byte) (n, oobn, flags int, from *net.IPAddr, err error) {
	if c.sniffer == nil {
		return c.IPConn.ReadMsgIP(b, oob)
	}
	n, err = c.sniffer.Read(b)
	if err != nil {
		return 0, 0, 0, nil, err
	}
	// form the net ip addr from the ip header
	// using the source ip address
	ip := make([]byte, 4)
	copy(ip, b[12:16])
	from = &net.IPAddr{IP: ip}
	return n, 0, 0, from, nil
}

func (c *ipConn) Close() error {
	if c.sniffer != nil {
		c.sniffer.Close()
	}
	return c.IPConn.Close()
}
