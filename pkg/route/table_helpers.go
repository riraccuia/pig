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

package route

import (
	"math/big"
	"net"
)

// bitWidth returns the address width in bits for the table's family.
func (t *Table) bitWidth() int {
	switch t.family {
	case FamilyInet:
		return 32
	case FamilyInet6:
		return 128
	default:
		panic("invalid family")
	}
}

// commonBits returns the number of equal leading bits shared by two prefixes,
// capped at the family's address width.
//
// example:
//
//	prefix1 = 11000000.10101000.00000000.00000000
//	prefix2 = 11000000.10101000.00000000.00000001
//	XOR res = 00000000.00000000.00000000.00000001
//	shared  = 31
func (t *Table) commonBits(prefix1 *big.Int, prefix2 *big.Int) int {
	width := t.bitWidth()
	x := new(big.Int).Xor(prefix1, prefix2)
	if x.BitLen() == 0 {
		return width
	}
	return width - x.BitLen()
}

// maskPrefix returns a copy of key with all bits at or beyond position n
// cleared, producing a clean network key of length n.
func (t *Table) maskPrefix(key *big.Int, n int) *big.Int {
	width := t.bitWidth()
	out := new(big.Int).Set(key)
	for pos := n; pos < width; pos++ {
		out.SetBit(out, width-1-pos, 0)
	}
	return out
}

func calculateNetworkAddress(ipnet *net.IPNet) net.IP {
	ones, total := ipnet.Mask.Size()
	if ones == total {
		return ipnet.IP
	}
	return ipnet.IP.Mask(ipnet.Mask)
}

// routeToTablePrefix converts a route to a prefix for the routing table.
func routeToTablePrefix(route *Route) *big.Int {
	ip := calculateNetworkAddress(route.Destination)
	if ip.To4() != nil {
		return big.NewInt(0).SetBytes(ip.To4())
	}
	if ip.To16() != nil {
		return big.NewInt(0).SetBytes(ip.To16())
	}
	return nil
}

// routeToPrefixBits return the route's prefix length in bits.
func routeToPrefixBits(route *Route) uint32 {
	ones, _ := route.Destination.Mask.Size()
	return uint32(ones)
}

// getBit returns the bit at the given position in the prefix.
func (t *Table) getBit(prefix *big.Int, pos int) uint8 {
	var length int
	switch t.family {
	case FamilyInet:
		length = 32
	case FamilyInet6:
		length = 128
	default:
		panic("invalid family")
	}
	return uint8(prefix.Bit(length - 1 - pos))
}
