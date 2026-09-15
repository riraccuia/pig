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

package icmp

import (
	"fmt"
	"net"
)

func getAdapterAddr(adapterName string) (*net.IPAddr, *net.Interface, error) {
	iface, err := net.InterfaceByName(adapterName)
	if err != nil {
		return nil, iface, fmt.Errorf("failed to get interface: %w", err)
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, iface, fmt.Errorf("failed to get addresses: %w", err)
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return &net.IPAddr{IP: ipnet.IP}, iface, nil
			}
		}
	}
	return nil, nil, fmt.Errorf("no valid address found")
}
