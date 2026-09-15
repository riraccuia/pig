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

package stun

import (
	"context"
	"net"
	"testing"
)

func TestServerUDPBindingRequest(t *testing.T) {
	var bound *net.UDPAddr
	srv, err := NewServer(&ServerConfig{
		Logger:  NoopLoggerFunc,
		Workers: 2,
		UDPListenFunc: func(network string, laddr *net.UDPAddr) (*net.UDPConn, error) {
			c, err := net.ListenUDP(network, laddr)
			if err != nil {
				return nil, err
			}
			bound = c.LocalAddr().(*net.UDPAddr)
			return c, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listenAddr := &net.UDPAddr{IP: net.IPv4zero}
	if err := srv.Listen(ctx, listenAddr); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	clientConn, err := net.DialUDP("udp", &net.UDPAddr{IP: net.IPv4zero}, bound)
	if err != nil {
		t.Fatalf("DialUDP failed: %v", err)
	}
	defer clientConn.Close()

	local := clientConn.LocalAddr().(*net.UDPAddr)

	result, err := QueryServerUDP(bound.String(), clientConn)
	if err != nil {
		t.Fatalf("QueryServerUDP failed: %v", err)
	}
	if !result.IP.Equal(local.IP) {
		t.Fatalf("unexpected IP: got %v want %v", result.IP, local.IP)
	}
	if result.Port != local.Port {
		t.Fatalf("unexpected port: got %d want %d", result.Port, local.Port)
	}
}

func TestServerTCPBindingRequest(t *testing.T) {
	var tcpBound *net.TCPAddr
	srv, err := NewServer(&ServerConfig{
		Logger:  NoopLoggerFunc,
		Workers: 2,
		TCPListenFunc: func(network string, laddr *net.TCPAddr) (*net.TCPListener, error) {
			l, err := net.ListenTCP(network, laddr)
			if err != nil {
				return nil, err
			}
			tcpBound = l.Addr().(*net.TCPAddr)
			return l, nil
		},
	})
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	listenAddr := &net.TCPAddr{IP: net.IPv4zero}
	if err := srv.Listen(ctx, listenAddr); err != nil {
		t.Fatalf("Listen failed: %v", err)
	}

	conn, err := net.DialTCP("tcp", &net.TCPAddr{IP: net.IPv4zero}, tcpBound)
	if err != nil {
		t.Fatalf("DialTCP failed: %v", err)
	}
	defer conn.Close()

	local := conn.LocalAddr().(*net.TCPAddr)

	result, err := QueryServerTCP(tcpBound.String(), conn)
	if err != nil {
		t.Fatalf("QueryServerTCP failed: %v", err)
	}
	if !result.IP.Equal(local.IP) {
		t.Fatalf("unexpected IP: got %v want %v", result.IP, local.IP)
	}
	if result.Port != local.Port {
		t.Fatalf("unexpected port: got %d want %d", result.Port, local.Port)
	}
}
