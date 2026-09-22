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
	"math/big"
	"net"
	"sync"
	"syscall"
)

type IPPool struct {
	network  *net.IPNet
	family   int
	maxHosts *big.Int
	used     map[uint128]bool
	mu       sync.Mutex
}

type uint128 struct {
	hi uint64
	lo uint64
}

func newIPPool(network *net.IPNet) *IPPool {
	family := syscall.AF_INET
	if network.IP.To4() == nil && network.IP.To16() != nil {
		family = syscall.AF_INET6
	}

	return &IPPool{
		network:  network,
		family:   family,
		maxHosts: big.NewInt(0).Sub(maxHosts(network), big.NewInt(2)), // Subtract network and broadcast addresses
		used:     make(map[uint128]bool),
	}
}

func (p *IPPool) key(n *big.Int) uint128 {
	if n.IsUint64() {
		return uint128{hi: 0, lo: n.Uint64()}
	}
	mask := new(big.Int).SetUint64(^uint64(0))
	return uint128{
		lo: new(big.Int).And(n, mask).Uint64(),
		hi: new(big.Int).Rsh(n, 64).Uint64(),
	}
}

func (p *IPPool) Allocate() (net.IP, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	one := big.NewInt(1)

	addr := p.ipToBigInt(p.network.IP)
	addr.Add(addr, one)

	for i := big.NewInt(0); i.Cmp(p.maxHosts) < 0; i.Add(i, one) {
		if !p.used[p.key(addr)] {
			p.used[p.key(addr)] = true
			return addr.Bytes(), nil
		}
		addr.Add(addr, one)
	}

	return nil, fmt.Errorf("no available IPs in pool")
}

func (p *IPPool) SetUsed(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.used[p.key(p.ipToBigInt(ip))] = true
}

func (p *IPPool) Release(ip net.IP) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.used, p.key(p.ipToBigInt(ip)))
}

func (p *IPPool) ipToBigInt(ip net.IP) *big.Int {
	switch p.family {
	case syscall.AF_INET:
		return big.NewInt(0).SetBytes(ip.To4())
	case syscall.AF_INET6:
		return big.NewInt(0).SetBytes(ip.To16())
	}
	return nil
}

func maxHosts(n *net.IPNet) *big.Int {
	ones, bits := n.Mask.Size()
	hostBits := bits - ones
	return big.NewInt(1).Lsh(big.NewInt(1), uint(hostBits))
}
