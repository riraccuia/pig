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
	"errors"
	"io"
	"net"
	"time"
)

type indexer interface {
	Index() int
}

type deadliner interface {
	SetDeadline(t time.Time) error
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

type TUNAdapter struct {
	io.ReadWriteCloser
	ip      net.IP
	ipv6    net.IP
	ipNet   *net.IPNet
	ipv6Net *net.IPNet
	ifName  string
}

func (t *TUNAdapter) IP() net.IP {
	return t.ip
}

func (t *TUNAdapter) IPNet() *net.IPNet {
	return t.ipNet
}

func (t *TUNAdapter) IP6() net.IP {
	return t.ipv6
}

func (t *TUNAdapter) IPNet6() *net.IPNet {
	return t.ipv6Net
}

func (t *TUNAdapter) Name() string {
	return t.ifName
}

func (t *TUNAdapter) Index() int {
	if indexer, ok := t.ReadWriteCloser.(indexer); ok {
		return indexer.Index()
	}
	iface, err := net.InterfaceByName(t.ifName)
	if err != nil {
		return -1
	}
	return iface.Index
}

func (t *TUNAdapter) SetDeadline(time time.Time) error {
	if deadliner, ok := t.ReadWriteCloser.(deadliner); ok {
		return deadliner.SetDeadline(time)
	}
	return errors.New("not implemented")
}

func (t *TUNAdapter) SetReadDeadline(time time.Time) error {
	if deadliner, ok := t.ReadWriteCloser.(deadliner); ok {
		return deadliner.SetReadDeadline(time)
	}
	return errors.New("not implemented")
}

func (t *TUNAdapter) SetWriteDeadline(time time.Time) error {
	if deadliner, ok := t.ReadWriteCloser.(deadliner); ok {
		return deadliner.SetWriteDeadline(time)
	}
	return errors.New("not implemented")
}
