/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.
 */

// Modifications Copyright 2026 Riccardo Raccuia
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

package conn

import (
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"
)

// SimpleBind is a Bind around a connected net.Conn.
type SimpleBind struct {
	c    net.Conn
	peer net.Addr
	port uint16

	opened atomic.Bool
}

// NewSimpleBind creates a Bind that receives from shared and sends to peer.
func NewSimpleBind(conn net.Conn) *SimpleBind {
	port := uint16(0)
	if ua, ok := conn.LocalAddr().(*net.UDPAddr); ok && ua != nil {
		port = uint16(ua.Port)
	}
	return &SimpleBind{
		c:    conn,
		peer: conn.RemoteAddr(),
		port: port,
	}
}

func (b *SimpleBind) Open(_ uint16) ([]conn.ReceiveFunc, uint16, error) {
	if !b.opened.CompareAndSwap(false, true) {
		return nil, 0, ErrBindAlreadyOpen
	}
	b.c.SetReadDeadline(time.Time{})
	return []conn.ReceiveFunc{b.receive}, b.port, nil
}

func (b *SimpleBind) receive(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
	n, err := b.c.Read(packets[0])
	if err != nil {
		if !b.opened.Load() {
			return 0, net.ErrClosed
		}
		return 0, err
	}
	sizes[0] = n
	eps[0] = &simpleEndpoint{addrPort: addrPortOf(b.peer)}
	return 1, nil
}

func (b *SimpleBind) Close() error {
	if !b.opened.CompareAndSwap(true, false) {
		return nil
	}
	b.c.SetReadDeadline(time.Now())
	return nil
}

func (b *SimpleBind) SetMark(uint32) error { return nil }

func (b *SimpleBind) BatchSize() int {
	return 1
}

func (b *SimpleBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	if !b.opened.Load() {
		return net.ErrClosed
	}
	for _, buf := range bufs {
		if _, err := b.c.Write(buf); err != nil {
			return err
		}
	}
	return nil
}

func (b *SimpleBind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &simpleEndpoint{addrPort: ap}, nil
}

type simpleEndpoint struct {
	addrPort netip.AddrPort
}

func (e *simpleEndpoint) ClearSrc()           {}
func (e *simpleEndpoint) SrcToString() string { return "" }
func (e *simpleEndpoint) DstToString() string { return e.addrPort.String() }
func (e *simpleEndpoint) DstToBytes() []byte {
	b, _ := e.addrPort.MarshalBinary()
	return b
}
func (e *simpleEndpoint) DstIP() netip.Addr { return e.addrPort.Addr() }
func (e *simpleEndpoint) SrcIP() netip.Addr { return netip.Addr{} }

func addrPortOf(a net.Addr) netip.AddrPort {
	ua, ok := a.(*net.UDPAddr)
	if !ok || ua == nil {
		return netip.AddrPort{}
	}
	ip, ok := netip.AddrFromSlice(ua.IP)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(ip.Unmap(), uint16(ua.Port))
}

var (
	_ conn.Bind     = (*SimpleBind)(nil)
	_ conn.Endpoint = (*simpleEndpoint)(nil)
)
