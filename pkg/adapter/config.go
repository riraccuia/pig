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

import "net"

// GetAdapterAddress retrieves the best adapter address for the given family, to be used
// immediately in order to establish an outbound connection.
func GetAdapterAddress(ifName string, family int) (net.IP, *net.IPNet, error) {
	return getAdapterAddress(ifName, family)
}

// rankIPAddr ranks an IP address based on its type.
// From highest to lowest: public, private (including IPv6 ULA), link-local, everything else.
func rankIPAddr(ip net.IP) int {
	var r int
	switch {
	case ip.IsGlobalUnicast() && !ip.IsPrivate():
		r = 3 // public
	case ip.IsPrivate():
		r = 2 // including IPv6 ULA
	case ip.IsLinkLocalUnicast():
		r = 1
	default:
		r = 0 // multicast, loopback, unspecified, …
	}
	return r
}
