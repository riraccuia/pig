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
// +build !windows

package adapter

import (
	"net"
)

// Tunnel represents a generic tunnel interface.
type Interface interface {
	Read(p []byte) (n int, err error)
	Write(p []byte) (n int, err error)
	Close() error
}

type TUNAdapter struct {
	iface  Interface
	ip     *net.IPNet
	ipv6   *net.IPNet
	ifName string
}

func (t *TUNAdapter) Read(b []byte) (int, error) {
	return t.iface.Read(b)
}

func (t *TUNAdapter) Write(b []byte) (int, error) {
	return t.iface.Write(b)
}

func (t *TUNAdapter) Close() error {
	return t.iface.Close()
}

func (t *TUNAdapter) IP() net.IP {
	if t.ip != nil {
		return t.ip.IP
	}
	return nil
}

func (t *TUNAdapter) IPNet() *net.IPNet {
	return t.ip
}

func (t *TUNAdapter) IP6() net.IP {
	if t.ipv6 != nil {
		return t.ipv6.IP
	}
	return nil
}

func (t *TUNAdapter) IPNet6() *net.IPNet {
	return t.ipv6
}

func (t *TUNAdapter) Name() string {
	return t.ifName
}

func (t *TUNAdapter) Index() int {
	iface, err := net.InterfaceByName(t.ifName)
	if err != nil {
		return -1
	}
	return iface.Index
}
