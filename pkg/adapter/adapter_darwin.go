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
	"fmt"
	"net"
	"os"
	"sync/atomic"

	"github.com/riraccuia/pig/pkg/common"
	"golang.org/x/sys/unix"
)

func newAdapter(config AdapterConfig) (common.TunnelAdapter, error) {
	ifName, utun, err := configureTUN(config)
	if err != nil {
		return nil, err
	}

	adapter := &TUNAdapter{
		iface:  utun,
		ifName: ifName,
	}

	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		return nil, fmt.Errorf("failed to get interface: %w", err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get interface addresses: %w", err)
	}

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		if ipnet.IP.To4() != nil {
			adapter.ip = ipnet
			continue
		}
		if ipnet.IP.To16() == nil {
			continue
		}
		if adapter.ipv6 == nil {
			adapter.ipv6 = ipnet
			continue
		}
		// Prefer non-link-local IPv6 address when available
		if !ipnet.IP.IsLinkLocalUnicast() && adapter.ipv6.IP.IsLinkLocalUnicast() {
			adapter.ipv6 = ipnet
		}
	}

	return adapter, nil
}

// utunAdapter is a wrapper around the utun device file descriptor.
// It reads and writes packets to the utun device file descriptor.
// The first 4 bytes of the packets are the 32bit BSD prefix for the IP family (AF_INET or AF_INET6).
// The remaining bytes are the packet data (ip datagram).
type utunAdapter struct {
	fd      *os.File
	r, w    []byte
	reading atomic.Bool
	writing atomic.Bool
}

func (uta *utunAdapter) Read(buf []byte) (int, error) {
	if !uta.reading.CompareAndSwap(false, true) {
		return 0, unix.EAGAIN
	}
	defer uta.reading.Store(false)

	if cap(uta.r) < len(buf)+4 {
		uta.r = make([]byte, len(buf)+4)
	}
	uta.r = uta.r[:len(buf)+4]

	n, err := uta.fd.Read(uta.r)
	copy(buf, uta.r[4:])
	return n - 4, err
}

func (uta *utunAdapter) Write(buf []byte) (int, error) {
	if len(buf) == 0 {
		return 0, nil
	}

	if !uta.writing.CompareAndSwap(false, true) {
		return 0, unix.EAGAIN
	}
	defer uta.writing.Store(false)

	if cap(uta.w) < len(buf)+4 {
		uta.w = make([]byte, len(buf)+4)
	}
	uta.w = uta.w[:len(buf)+4]

	ipFamily := buf[0] >> 4
	switch ipFamily {
	case 4:
		uta.w[3] = unix.AF_INET
	case 6:
		uta.w[3] = unix.AF_INET6
	default:
		return 0, fmt.Errorf("invalid IP family: %d", ipFamily)
	}

	copy(uta.w[4:], buf)

	n, err := uta.fd.Write(uta.w)
	return n - 4, err
}

func (uta *utunAdapter) Close() error {
	return uta.fd.Close()
}
