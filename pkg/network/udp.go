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

package network

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

// DialUDP uses a net.Dialer to dial a UDP connection and sets the SO_REUSEADDR option.
func DialUDP(network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	dialer := NewDialer(0)
	return dialUDP(dialer, network, laddr, raddr)
}

// ListenUDP uses a net.ListenConfig to listen on a UDP address and sets the SO_REUSEADDR option.
func ListenUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	return listenUDP(network, laddr)
}

func dialUDP(dialer *net.Dialer, network string, laddr, raddr *net.UDPAddr) (*net.UDPConn, error) {
	if laddr != nil {
		dialer.LocalAddr = laddr
	}

	conn, err := dialer.Dial(network, raddr.String())
	if err != nil {
		return nil, err
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("failed to convert to UDPConn")
	}

	return udpConn, nil
}

func listenUDP(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				// Set SO_REUSEADDR
				setSockoptReuseAddr(fd)
				setSockoptReusePort(fd)
			})
		},
	}

	conn, err := lc.ListenPacket(context.Background(), network, laddr.String())
	if err != nil {
		return nil, err
	}

	udpConn, ok := conn.(*net.UDPConn)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("failed to convert to UDPConn")
	}

	return udpConn, nil
}

// PunchUDP performs UDP hole punching from the specified source port to the target address.
// This creates a temporary opening in the NAT/firewall to allow direct UDP communication.
// A source port is required to be provided, either as an int or a *net.UDPConn. Use 0 for a random port.
func PunchUDP(connOrSourcePort any, targetAddr string) (sPort int, err error) {
	conn, ok := connOrSourcePort.(*net.UDPConn)
	if !ok {
		sourcePort, ok := connOrSourcePort.(int)
		if !ok {
			return 0, fmt.Errorf("invalid source port: %v", connOrSourcePort)
		}
		conn, err = net.ListenUDP("udp", &net.UDPAddr{
			IP:   nil, // Listen on all interfaces
			Port: sourcePort,
		})
		if err != nil {
			return 0, fmt.Errorf("failed to create UDP socket on port %d: %w", sourcePort, err)
		}
		defer conn.Close()
	}

	// Resolve target address
	targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve target address %s: %w", targetAddr, err)
	}

	// Get the actual local address we're using (especially important if sourcePort was 0)
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	sPort = localAddr.Port

	// Perform the hole punch by sending a byte to the target
	punchData := []byte{0x01}

	_, err = conn.WriteToUDP(punchData, targetUDPAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to send punch packet: %w", err)
	}

	return
}

// UDPPacketConn wraps a connected UDP connection to provide a net.PacketConn interface.
// This allows a connected UDP socket (created with net.DialUDP) to be used as if it were
// a listening UDP socket (created with net.ListenUDP).
type UDPPacketConn struct {
	co *net.UDPConn
}

// NewUDPPacketConn creates a new UDPPacketConn from a connected UDP connection.
// The connection should be one that was created using net.DialUDP.
func NewUDPPacketConn(co *net.UDPConn) *UDPPacketConn {
	if co == nil {
		panic("conn cannot be nil")
	}

	return &UDPPacketConn{
		co: co,
	}
}

func (pc *UDPPacketConn) LocalAddr() net.Addr {
	return pc.co.LocalAddr()
}

func (pc *UDPPacketConn) RemoteAddr() net.Addr {
	return pc.co.RemoteAddr()
}

func (pc *UDPPacketConn) Write(p []byte) (n int, err error) {
	return pc.co.Write(p)
}

func (pc *UDPPacketConn) Read(p []byte) (n int, err error) {
	return pc.co.Read(p)
}

func (pc *UDPPacketConn) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	n, err = pc.co.Read(p)
	return n, pc.co.RemoteAddr(), err
}

// WriteTo writes a packet with payload p to addr.
func (pc *UDPPacketConn) WriteTo(p []byte, addr net.Addr) (n int, err error) {
	return pc.co.Write(p)
}

func (pc *UDPPacketConn) SetReadBuffer(bytes int) error {
	return pc.co.SetReadBuffer(bytes)
}

func (pc *UDPPacketConn) SetWriteBuffer(bytes int) error {
	return pc.co.SetWriteBuffer(bytes)
}

func (pc *UDPPacketConn) SetDeadline(t time.Time) error {
	return pc.co.SetDeadline(t)
}

func (pc *UDPPacketConn) SetReadDeadline(t time.Time) error {
	return pc.co.SetReadDeadline(t)
}

func (pc *UDPPacketConn) SetWriteDeadline(t time.Time) error {
	return pc.co.SetWriteDeadline(t)
}

func (pc *UDPPacketConn) Close() error {
	return pc.co.Close()
}
