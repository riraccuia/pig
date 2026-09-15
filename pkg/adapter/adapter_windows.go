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

	"github.com/riraccuia/pig/pkg/common"
)

const tunName = "pig"

func newAdapter(config AdapterConfig) (common.TunnelAdapter, error) {
	//wintun.SetLogger(nil)

	adapter, err := CreateTUNWithRequestedGUID(tunName, WintunStaticRequestedGUID)
	if err != nil {
		return nil, fmt.Errorf("failed to create wintun adapter: %v", err)
	}

	if err := configureWinTun(tunName, config); err != nil {
		adapter.Close()
		return nil, fmt.Errorf("failed to configure adapter: %v", err)
	}

	iface, err := net.InterfaceByName(adapter.Name())
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
