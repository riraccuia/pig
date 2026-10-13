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

package network

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
)

// GenerateIPPrefix takes a base prefix (IPv4 or IPv6), in the form of "192.168.1.1/24" or "fd00::1/64", and a target prefix length,
// and generates a smaller prefix that's within the base network. The target prefix length must be smaller than the base prefix length.
// If withFirstUsableHost is true, the final prefix will be formed using the first usable host instead of the network address.
func GenerateIPPrefix(basePrefix string, targetPrefixLen int, withFirstUsableHost bool) (netip.Prefix, error) {
	return generateIPPrefix(basePrefix, targetPrefixLen, withFirstUsableHost, true)
}

func generateIPPrefix(basePrefix string, targetPrefixLen int, withFirstUsableHost bool, useRandomSubnetIndex bool) (netip.Prefix, error) {
	base, err := netip.ParsePrefix(basePrefix)
	if err != nil {
		return netip.Prefix{}, err
	}
	base = base.Masked()
	addr := base.Addr()
	totalBits := addr.BitLen() // 32 or 128
	baseBits := base.Bits()
	if targetPrefixLen == baseBits {
		if withFirstUsableHost && targetPrefixLen < totalBits {
			return netip.PrefixFrom(addr.Next(), targetPrefixLen), nil
		}
		return base, nil
	}
	if targetPrefixLen < baseBits || targetPrefixLen > totalBits {
		return netip.Prefix{}, fmt.Errorf("invalid target prefix length %d", targetPrefixLen)
	}

	// Calculate number of target subnets that can fit in the base network
	// 2^(targetPrefix - baseBits)
	bitsDiff := int64(targetPrefixLen - baseBits)
	numSubnets := new(big.Int).Lsh(big.NewInt(1), uint(bitsDiff))

	subnetIndex := big.NewInt(0)
	if useRandomSubnetIndex {
		// Pick a random subnet index
		subnetIndex, err = rand.Int(rand.Reader, numSubnets)
		if err != nil {
			return netip.Prefix{}, err
		}
	}

	// Calculate host size of the target subnet: 2^(totalBits - targetPrefix)
	hostBits := uint(totalBits - targetPrefixLen)
	subnetHostSize := new(big.Int).Lsh(big.NewInt(1), hostBits)

	// Convert base IP bytes into a big.Int
	baseInt := new(big.Int).SetBytes(addr.AsSlice())

	// Calculate total offset: randomIndex * subnetHostSize
	offset := new(big.Int).Mul(subnetIndex, subnetHostSize)

	// Compute final network address
	subnetInt := new(big.Int).Add(baseInt, offset)

	ipBytes := make(net.IP, totalBits/8)
	subnetInt.FillBytes(ipBytes)

	out, ok := netip.AddrFromSlice(ipBytes)
	if !ok {
		return netip.Prefix{}, errors.New("invalid address")
	}
	if withFirstUsableHost && targetPrefixLen < totalBits {
		out = out.Next()
	}
	return netip.PrefixFrom(out, targetPrefixLen), nil
}
