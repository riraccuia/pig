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

package adapter

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/network"
)

const (
	stdioIPHeaderLen  = 20
	stdioUDPHeaderLen = 8
	stdioHeaderLen    = stdioIPHeaderLen + stdioUDPHeaderLen
	stdioUDPPort      = 1234
	stdioBlockSize    = 1<<16 - 1
)

var _ common.TunnelAdapter = (*StdioAdapter)(nil)

// StdioAdapter implements common.TunnelAdapter by bridging stdin/stdout with a
// minimal fake IPv4+UDP header shim for netcat mode. Checksums are left zero;
// headers exist only so client/server packet parsers see a length-delimited IP packet.
// Datagram source IP is always 0.0.0.0; destination is the first usable host in the
// configured subnet.
type StdioAdapter struct {
	ipNet    *net.IPNet
	in       io.ReadCloser
	out      *os.File
	localIP  net.IP
	remoteIP net.IP
	closed   atomic.Bool
	mtu      int
	// blockSize is the maximum amount of data
	// that can be read from stdin at once.
	blockSize int
}

// NewStdioAdapter creates a StdioAdapter from the same AdapterConfig shape used by TUN.
// cfg.Address must contain an IPv4 CIDR; identity (IP/IPNet) comes from that prefix.
func NewStdioAdapter(cfg AdapterConfig) (*StdioAdapter, error) {
	localIP, ipNet, err := parseCIDRForStdio(cfg.Address)
	if err != nil {
		return nil, err
	}
	remoteIP, err := getFirstSubnetHost(ipNet, localIP)
	if err != nil {
		return nil, err
	}
	return &StdioAdapter{
		localIP:   localIP,
		remoteIP:  remoteIP,
		ipNet:     ipNet,
		in:        newStdioReader(),
		out:       os.Stdout,
		mtu:       cfg.MTU,
		blockSize: stdioBlockSize,
	}, nil
}

func parseCIDRForStdio(addresses []string) (net.IP, *net.IPNet, error) {
	if len(addresses) == 0 {
		return nil, nil, fmt.Errorf("address is required")
	}
	ip, ipNet, err := net.ParseCIDR(addresses[0])
	if err != nil {
		return nil, nil, fmt.Errorf("address %s: %w", addresses[0], err)
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return nil, nil, fmt.Errorf("address %s: expected IPv4", addresses[0])
	}
	_, bits := ipNet.Mask.Size()
	if bits != 32 {
		return nil, nil, fmt.Errorf("address %s: need IPv4 prefix", addresses[0])
	}
	return ip4, ipNet, nil
}

// getFirstSubnetHost returns the first usable host in ipNet that is not localIP, or the
// network address if the prefix is /32.
func getFirstSubnetHost(ipNet *net.IPNet, localIP net.IP) (net.IP, error) {
	ones, _ := ipNet.Mask.Size()
	if ones == 32 {
		return ipNet.IP.To4(), nil
	}
	addr, ok := netip.AddrFromSlice(ipNet.IP.To4())
	if !ok {
		return nil, fmt.Errorf("invalid network address %s", ipNet)
	}
	local, ok := netip.AddrFromSlice(localIP.To4())
	if !ok {
		return nil, fmt.Errorf("invalid local address %s", localIP)
	}

	prefix := netip.PrefixFrom(addr, ones).Masked()

	var peer netip.Addr
	for peer = prefix.Addr().Next(); ; peer = peer.Next() {
		if peer.IsUnspecified() || !peer.IsValid() || !prefix.Contains(peer) {
			return nil, fmt.Errorf("no peer host available in %s", ipNet)
		}
		if peer == local {
			continue
		}
		return peer.AsSlice(), nil
	}

}

func (a *StdioAdapter) Read(buf []byte) (int, error) {
	if a.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(buf) < stdioHeaderLen {
		return 0, io.ErrShortBuffer
	}

	maxPayload := min(a.blockSize-stdioHeaderLen, len(buf)-stdioHeaderLen)

	n, err := a.in.Read(buf[stdioHeaderLen : stdioHeaderLen+maxPayload])
	if n == 0 && err != nil {
		if a.closed.Load() {
			return 0, net.ErrClosed
		}
		return 0, err
	}

	// Partial read with error (e.g. EOF after some bytes): still emit a packet;
	// the error is returned only when no payload was read.

	totalLen := stdioHeaderLen + n
	a.wrapPayload(buf[:totalLen], net.IPv4zero, a.remoteIP, n)

	if err != nil && !errors.Is(err, io.EOF) {
		return totalLen, err
	}
	return totalLen, nil
}

func (a *StdioAdapter) Write(b []byte) (int, error) {
	if a.closed.Load() {
		return 0, net.ErrClosed
	}
	if len(b) < stdioHeaderLen {
		return 0, fmt.Errorf("packet too short: %d", len(b))
	}

	pkt := network.IPv4Packet(b)
	if pkt.Version() != 4 {
		return 0, fmt.Errorf("unsupported IP version: %d", pkt.Version())
	}

	payloadOff := pkt.PayloadOffset() + stdioUDPHeaderLen

	if payloadOff > len(b) || payloadOff < stdioHeaderLen {
		return 0, fmt.Errorf("invalid payload offset: %d", payloadOff)
	}

	end := pkt.TotalLength()
	if end > len(b) || end < stdioHeaderLen || end < payloadOff {
		return 0, fmt.Errorf("invalid packet length: %d", end)
	}

	if _, err := a.out.Write(b[payloadOff:end]); err != nil {
		if a.closed.Load() {
			return 0, net.ErrClosed
		}
		return 0, err
	}
	return len(b), nil
}

func (a *StdioAdapter) Close() error {
	if !a.closed.CompareAndSwap(false, true) {
		return nil
	}
	return a.in.Close()
}

func (a *StdioAdapter) MTU() int {
	return a.mtu
}

func (a *StdioAdapter) BlockSize() int {
	return a.blockSize
}

func (a *StdioAdapter) IP() net.IP {
	return a.localIP
}

func (a *StdioAdapter) IPNet() *net.IPNet {
	return a.ipNet
}

func (a *StdioAdapter) IP6() net.IP {
	return nil
}

func (a *StdioAdapter) IPNet6() *net.IPNet {
	return nil
}

func (a *StdioAdapter) Name() string {
	return "stdio"
}

func (a *StdioAdapter) Index() int {
	return -1
}

func (a *StdioAdapter) SetDeadline(t time.Time) error {
	err := a.SetReadDeadline(t)
	if err != nil {
		return err
	}
	return a.SetWriteDeadline(t)
}

func (a *StdioAdapter) SetReadDeadline(t time.Time) error {
	return a.in.(*stdioReader).SetReadDeadline(t)
}

func (a *StdioAdapter) SetWriteDeadline(t time.Time) error {
	return a.out.SetWriteDeadline(t)
}

func (a *StdioAdapter) wrapPayload(pkt []byte, src, dst net.IP, payloadLen int) {
	udpLen := stdioUDPHeaderLen + payloadLen
	totalLen := stdioIPHeaderLen + udpLen
	// make sure totalLen does not exceed 65535
	if totalLen > 0xFFFF {
		panic(fmt.Errorf("totalLen=%d exceeds 65535", totalLen))
	}
	// IPv4 header
	pkt[0] = 0x45 // version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[8] = 1  // TTL
	pkt[9] = 17 // UDP
	copy(pkt[12:16], src.To4())
	copy(pkt[16:20], dst.To4())
	// UDP header
	binary.BigEndian.PutUint16(pkt[20:22], stdioUDPPort)
	binary.BigEndian.PutUint16(pkt[22:24], stdioUDPPort)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))
}

// stdioReader copies stdin into a pipe so adapter Read waits on the pipe,
// not on the TTY/stdin fd.
//
// Closing os.Stdin to unblock a stuck terminal Read is unreliable: the tunnel
// can tear down while Read remains blocked the user hits Enter.
// This problem affects at least Darwin/macOS, but other OSes may be affected too.
// Closing the pipe writer wakes Read promptly without waiting for the user to hit Enter.
type stdioReader struct {
	stdin, pr, pw *os.File
}

func newStdioReader() *stdioReader {
	pr, pw, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	r := &stdioReader{stdin: os.Stdin, pr: pr, pw: pw}
	go r.copyLoop()
	return r
}

func (r *stdioReader) copyLoop() {
	_, _ = io.Copy(r.pw, r.stdin)
	_ = r.pw.Close()
}

func (r *stdioReader) SetReadDeadline(t time.Time) error {
	return r.pr.SetReadDeadline(t)
}

func (r *stdioReader) Read(buf []byte) (int, error) {
	return r.pr.Read(buf)
}

func (r *stdioReader) Close() error {
	return r.pw.Close()
}
