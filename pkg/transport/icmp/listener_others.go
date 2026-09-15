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

//go:build !darwin
// +build !darwin

package icmp

import (
	"fmt"
	"net"
)

type ipConn struct {
	*net.IPConn
}

func newIcmpIPConn(bindAddr *net.IPAddr, iface *net.Interface, isServer bool) (*ipConn, error) {
	conn, err := net.ListenIP("ip4:icmp", bindAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to create ICMP socket: %w", err)
	}
	return &ipConn{
		IPConn: conn,
	}, nil
}
