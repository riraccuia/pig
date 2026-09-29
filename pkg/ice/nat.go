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

package ice

import (
	"crypto/rand"
	"math/big"
	"net"
	"slices"

	"github.com/riraccuia/pig/pkg/stun"
	"github.com/riraccuia/pig/pkg/transport"
)

func (pc *PathConnector) discoverNATType() int {
	result, err := stun.DiscoverNATBehavior(pc.opts.STUNServer, &stun.NATDiscoveryOptions{Scope: stun.DiscoveryFull})
	if err != nil {
		pc.opts.Logger.Errorf("failed to discover NAT behavior: %v", err)
	}
	if result != nil && result.IsBehindNAT() {
		pc.opts.Logger.Infof("NAT detected: %s", result.String())
	}
	return getNATType(result)
}

func getNATType(result *stun.NATDiscoveryResult) int {
	if result == nil {
		return 0
	}
	return int(result.Mapping)
}

// appendNATConnectPaths takes a list of connection paths and appends NAT-TRAVERSAL paths to it, if applicable.
func (pc *PathConnector) appendNATConnectPaths(paths []*ConnectPath, ourNatType, theirNatType int) []*ConnectPath {
	var natCp []*ConnectPath

	paths = slices.DeleteFunc(paths, func(c *ConnectPath) bool {
		if c.RemoteIP.IsPrivate() {
			return false
		}
		if c.LocalNet.Contains(c.RemoteIP) {
			return false
		}
		paths := pc.generateNATConnectPathsFromPublicPath(c, ourNatType, theirNatType)
		if len(paths) == 0 {
			return false
		}
		pc.opts.Logger.Debugf("ICE: generated %d NAT-T paths from public path: %s", len(paths), c)
		natCp = append(natCp, paths...)
		return true
	})

	if len(natCp) > 0 {
		paths = append(paths, natCp...)
	}
	return paths
}

// generateNATConnectPathsFromPublicPath takes a given public path and NAT types for both endpoints and returns a set of connection paths that should
// be attempted. An empty result means that the original path is valid as is.
//
// The returned paths, when simultaneously attempted, maximize the chances for two endpoints to establish a connection even when one is behind
// "symmetric", or "address dependent" NAT.
// The idea is that if at least one port of the TCP/UDP tuple can be predicted (e.g. for the machine behind simple NAT), we are left with a single port
// that's ultimately unknown to both sides, and it's a number in the 0-65535 range.
//
// The "birthday problem" suggests that it is not that hard to find a collision in that range from a purely probabilistic angle.
// Using its generalized formula, we determine the amount of uint16 numbers `n` one has to generate for a ~50% success rate that the resulting set will
// contain at least one duplicate:
//
//	m = desired probability of success (in this case 0.5, or 50%)
//	T = total items to consider
//	n = SQRT(-2ln(1-m)) x SQRT(T)
//
// We assume that the first 1024 TCP/UDP ports are reserved for well-known services, and calculate `n` as follows.
// We're looking for a ~50% chances of a duplicate:
//
//	n = SQRT(-2ln(1-0.5)) x SQRT(65535-1024)
//	n = 1.17 x 254
//	n = 297
//
// Only 297 dice rolls needed for a 1/2 chance of a collision. Not bad.
// What if we had each machine attempt `n/2` ports and compare the results?
// How does this affect the probability of a collision?
// Will the two sides find matching tuples with an acceptable success rate?
// Turns out it's still quite okay, and what this method does today.
//
// Early testing shows that with each side attempting 150 ports (currently hardcoded), success drops from 50% to 30%.
// Still better than having to resort to a TURN server.
func (pc *PathConnector) generateNATConnectPathsFromPublicPath(cp *ConnectPath, ourNatType, theirNatType int) (paths []*ConnectPath) {
	if ourNatType < int(stun.MappingAddressDependent) && theirNatType < int(stun.MappingAddressDependent) {
		// no need to generate NAT connect paths
		return nil
	}
	switch cp.Protocol {
	case transport.ICEProtocolTLSInICMP:
		return nil
	default:
	}
	// generate 150 random ints in the range 1025-65535
	// do not allow duplicates
	portsMap := make(map[int]struct{})
	ports := []int{}
	for i := 0; i < 150; i++ {
		p, _ := rand.Int(rand.Reader, big.NewInt(65535-1025+1))
		port := int(p.Int64()) + 1025
		if _, ok := portsMap[port]; ok {
			i--
			continue
		}
		portsMap[port] = struct{}{}
		ports = append(ports, port)
	}
	//slices.Sort(ports)
	if ourNatType == int(stun.MappingEndpointIndependent) {
		// our NAT type is endpoint independent
		for _, port := range ports {
			addPath := *cp
			addPath.RemoteAddr = AddressFrom(addPath.Protocol.Network, cp.RemoteIP, port)
			addPath.BindAgent = addPath.BindAgent.Clone()
			//pc.opts.Logger.Infof("NAT CONNECT PATH: %v", addPath)
			paths = append(paths, &addPath)
		}
		return paths
	}
	// our NAT type is either address dependent or address and port dependent

	// get local ip from local addr
	var localIP net.IP
	switch cp.Protocol.Network {
	case "udp":
		localIP = cp.LocalAddr.(*net.UDPAddr).IP
	case "tcp":
		localIP = cp.LocalAddr.(*net.TCPAddr).IP
	case "icmp":
		localIP = cp.LocalAddr.(*net.IPAddr).IP
	}
	for _, port := range ports {
		addPath := *cp
		addPath.LocalAddr = AddressFrom(addPath.Protocol.Network, localIP, port)
		addPath.BindAgent = addPath.BindAgent.Clone()
		paths = append(paths, &addPath)
	}
	return paths
}
