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

//go:build !windows

package network

import (
	"context"
	"fmt"
	"net"
)

func DialWithDialer(dialer *net.Dialer, network string, laddr, raddr net.Addr) (net.Conn, error) {
	switch network {
	case "tcp":
		tcpLAddr, ok := laddr.(*net.TCPAddr)
		if !ok {
			return nil, fmt.Errorf("invalid TCP address: %s", laddr)
		}
		tcpRAddr, ok := raddr.(*net.TCPAddr)
		if !ok {
			return nil, fmt.Errorf("invalid TCP address: %s", raddr)
		}
		return dialTCP(context.Background(), dialer, network, tcpLAddr, tcpRAddr)
	case "udp":
		udpLAddr, ok := laddr.(*net.UDPAddr)
		if !ok {
			return nil, fmt.Errorf("invalid UDP address: %s", laddr)
		}
		udpRAddr, ok := raddr.(*net.UDPAddr)
		if !ok {
			return nil, fmt.Errorf("invalid UDP address: %s", raddr)
		}
		return dialUDP(context.Background(), dialer, network, udpLAddr, udpRAddr)
	default:
		return nil, fmt.Errorf("unsupported network: %s", network)
	}
}
