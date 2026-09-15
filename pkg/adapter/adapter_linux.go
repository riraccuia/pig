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
	"io"
	"net"
	"os"
	"unsafe"

	"github.com/riraccuia/pig/pkg/common"
	"golang.org/x/sys/unix"
)

func newAdapter(config AdapterConfig) (common.TunnelAdapter, error) {
	ifName, tun, err := configureTUN(config)
	if err != nil {
		return nil, err
	}

	adapter := &TUNAdapter{
		iface:  tun,
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

func (a *TUNAdapter) Queues() []io.ReadWriteCloser {
	return a.iface.(*tunAdapter).queues
}

type tunAdapter struct {
	queues  []io.ReadWriteCloser
	devName string
}

func (a *tunAdapter) NewQueue(ifr ifreq, id int) (io.ReadWriteCloser, error) {
	queueFd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open /dev/net/tun: %w", err)
	}

	if err = unix.IoctlSetInt(queueFd, TUNSETIFF, int(uintptr(unsafe.Pointer(&ifr)))); err != nil {
		return nil, fmt.Errorf("failed to create TUN queue: %w", err)
	}

	err = unix.SetNonblock(queueFd, true)
	if err != nil {
		return nil, fmt.Errorf("failed to set non-blocking mode: %w", err)
	}

	return os.NewFile(uintptr(queueFd), fmt.Sprintf("/dev/net/tun/%v-queue%v", a.devName, id)), nil
}

func (a *tunAdapter) Write(p []byte) (n int, err error) {
	return a.queues[0].Write(p)
}

func (a *tunAdapter) Read(p []byte) (n int, err error) {
	return a.queues[0].Read(p)
}

func (a *tunAdapter) Close() error {
	for _, fd := range a.queues {
		fd.Close()
	}
	return nil
}
