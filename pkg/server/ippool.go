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

package server

import (
	"fmt"
	"math"
	"net"
	"sync"
)

type IPPool struct {
	network *net.IPNet
	used    map[string]bool
	mu      sync.Mutex
}

func newIPPool(network *net.IPNet) *IPPool {
	return &IPPool{
		network: network,
		used:    make(map[string]bool),
	}
}

func (p *IPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	ip := make(net.IP, len(p.network.IP))
	copy(ip, p.network.IP)

	// Skip network address and first usable IP (reserved for server)
	incrementIP(ip) // Skip network address
	incrementIP(ip) // Skip first usable IP (reserved for server)

	for i := 2; i < maxHostsInNetwork(p.network)-1; i++ {
		if !p.used[ip.String()] {
			p.used[ip.String()] = true
			return ip, nil
		}
		incrementIP(ip)
	}

	return nil, fmt.Errorf("no available IPs in pool")
}

func (p *IPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, ip.String())
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}

func maxHostsInNetwork(n *net.IPNet) int {
	ones, bits := n.Mask.Size()
	hostBits := bits - ones
	if hostBits < 64 {
		return 1 << uint(hostBits)
	}
	return math.MaxInt32
}
