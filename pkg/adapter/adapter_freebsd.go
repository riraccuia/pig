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

//go:build freebsd

package adapter

import (
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"golang.org/x/sys/unix"
)

func NewTunAdapter(config *AdapterConfig) (common.TunnelAdapter, error) {
	ifName, tun, err := configureTUN(config)
	if err != nil {
		return nil, err
	}

	adapter := &TUNAdapter{
		ReadWriteCloser: tun,
		ifName:          ifName,
		mtu:             config.MTU,
	}

	ip, ipNet, err := getAdapterAddress(ifName, unix.AF_INET)
	if err == nil {
		adapter.ip = ip
		adapter.ipNet = ipNet
	}

	ip, ipNet, err = getAdapterAddress(ifName, unix.AF_INET6)
	if err == nil {
		adapter.ipv6 = ip
		adapter.ipv6Net = ipNet
	}

	return adapter, nil
}

// tunAdapter wraps a FreeBSD /dev/tun file descriptor in IFHEAD mode.
// The first 4 bytes of each frame are the address family (AF_INET or AF_INET6);
// the rest is the IP datagram.
type tunAdapter struct {
	fd      *os.File
	name    string
	r, w    []byte
	reading atomic.Bool
	writing atomic.Bool
}

func (a *tunAdapter) Read(buf []byte) (int, error) {
	if !a.reading.CompareAndSwap(false, true) {
		return 0, unix.EAGAIN
	}
	defer a.reading.Store(false)

	if cap(a.r) < len(buf)+4 {
		a.r = make([]byte, len(buf)+4)
	}
	a.r = a.r[:len(buf)+4]

	n, err := a.fd.Read(a.r)
	copy(buf, a.r[4:n])
	return n - 4, err
}

func (a *tunAdapter) Write(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	if !a.writing.CompareAndSwap(false, true) {
		return 0, unix.EAGAIN
	}
	defer a.writing.Store(false)

	if cap(a.w) < len(buf)+4 {
		a.w = make([]byte, len(buf)+4)
	}
	a.w = a.w[:len(buf)+4]

	a.w[0], a.w[1], a.w[2] = 0, 0, 0
	ipFamily := buf[0] >> 4
	switch ipFamily {
	case 4:
		a.w[3] = unix.AF_INET
	case 6:
		a.w[3] = unix.AF_INET6
	default:
		return 0, fmt.Errorf("invalid IP family: %d", ipFamily)
	}

	copy(a.w[4:], buf)

	n, err := a.fd.Write(a.w)
	return n - 4, err
}

func (a *tunAdapter) SetDeadline(t time.Time) error {
	return a.fd.SetDeadline(t)
}

func (a *tunAdapter) SetReadDeadline(t time.Time) error {
	return a.fd.SetReadDeadline(t)
}

func (a *tunAdapter) SetWriteDeadline(t time.Time) error {
	return a.fd.SetWriteDeadline(t)
}

func (a *tunAdapter) Close() error {
	err := a.fd.Close()
	// TUNSIFPID already destroys the iface when the last fd closes; this
	// covers the case where ownership was never taken.
	_ = destroyTUN(a.name)
	return err
}
