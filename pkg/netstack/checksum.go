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

package netstack

import "net/netip"

// checksumValid verifies a TCP or UDP checksum over the IPv4 or IPv6
// pseudo-header (RFC 9293 §3.1, RFC 768, RFC 8200 §8.1). A valid transport
// payload sums to 0xffff.
func checksumValid(proto uint8, src, dst netip.Addr, payload []byte) bool {
	length := uint32(len(payload))
	var sum uint32
	sum = addWords(sum, src.AsSlice())
	sum = addWords(sum, dst.AsSlice())
	sum += uint32(proto)
	sum += length>>16 + length&0xffff
	sum = addWords(sum, payload)
	return foldChecksum(sum) == 0xffff
}

func addWords(sum uint32, b []byte) uint32 {
	n := len(b) &^ 1
	for i := 0; i < n; i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b) > n {
		sum += uint32(b[n]) << 8
	}
	return sum
}

func foldChecksum(sum uint32) uint32 {
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return sum
}
