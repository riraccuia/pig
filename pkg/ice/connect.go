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
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"slices"
	"time"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/stun"
)

func (pc *PathConnector) GetConnectPaths(ctx context.Context, target *config.ConnectTarget) (cp []*ConnectPath, scheduledAt time.Time, err error) {
	localEndpoints, err := GetLocalEndpoints("", pc.excludedAdapters)
	if err != nil {
		return nil, time.Time{}, err
	}

	// NAT behavior can change over time or under certain conditions, so we need to discover it again for each new negotiation
	natType := pc.discoverNATType()

	var (
		offerCandidates []message.ICECandidate
		localInfo       map[localCandidateKey]localCandidateInfo
	)

	offerCandidates, localInfo = buildLocalCandidates(pc.pigProtos, localEndpoints, uint16(target.SrcPort))
	offerCandidates = append(offerCandidates, buildReflexiveCandidates(pc.pigProtos, localEndpoints, localInfo, pc.opts)...)
	offerCandidates = dedupCandidates(offerCandidates)

	var (
		offer, answer *message.ICEMessage
	)

	offer, err = message.GenerateICEMessage(message.ICEMessageTypeOffer, offerCandidates)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("failed to generate ICE offer: %w", err)
	}

	offer.ConnectOffsetDuration = pc.opts.ConnectOffset
	offer.NATType = natType

	answer, err = signaling.GatherICECandidates(ctx, pc.opts, target.Address, offer)
	if err != nil {
		return
	}

	pc.opts.Logger.Tracef("ICE: raw candidates from answer: %v", answer.Candidates)

	iceAuth := &stun.IceAuth{
		LocalUfrag:     offer.Credentials.Username,
		LocalPassword:  offer.Credentials.Password,
		RemoteUfrag:    answer.Credentials.Username,
		RemotePassword: answer.Credentials.Password,
	}

	var bindLogger stun.LoggerFunc
	if pc.opts.Logger != nil {
		bindLogger = pc.opts.Logger.PrintLevel
	}

	for _, candidate := range answer.Candidates {
		targetIP := net.ParseIP(candidate.Address)
		for _, tr := range pc.pigProtos {
			if tr.Network != candidate.Protocol {
				continue
			}
			if tr.ComponentID != candidate.ComponentID {
				continue
			}
			for _, localEndpoint := range localEndpoints {
				if getFamilyForIP(localEndpoint.IP) != getFamilyForIP(targetIP) {
					continue
				}
				localNet := localEndpoint.Net
				if candidate.Type == message.ICECandidateTypeHost && localNet != nil && localNet.IP.IsPrivate() && !localNet.Contains(targetIP) {
					// skip host candidates that are not in the same network as the target
					continue
				}
				info, ok := localInfo[makeLocalCandidateKey(tr, localEndpoint.IP)]
				if !ok {
					continue
				}
				connect := getPathForProto(tr, localNet, localEndpoint.IP, nil, uint16(info.port))
				connect.BindAgent = stun.NewBindingAgent(stun.NewControllingICEBindingAgentConfig(bindLogger, iceAuth, info.priority))
				connect.ICEID = answer.SessionID
				connect.RemoteAddr = AddressFrom(connect.Protocol.Network, targetIP, candidate.Port)
				connect.RemoteIP = targetIP
				//connect.ScheduledAt = time.UnixMilli(answer.Timestamp).Add(offer.ConnectOffsetDuration)
				cp = append(cp, connect)
			}
		}
	}

	cp = dedupConnectPaths(cp)
	cp = sortConnectPaths(cp)

	if len(cp) == 0 {
		err = fmt.Errorf("no valid candidates found")
		return
	}

	pc.opts.Logger.Tracef("ICE: connect paths: %v", cp)

	var natCp []*ConnectPath

	cp = slices.DeleteFunc(cp, func(c *ConnectPath) bool {
		if c.RemoteIP.IsPrivate() {
			return false
		}
		if c.LocalNet.Contains(c.RemoteIP) {
			return false
		}
		paths := pc.generateNATConnectPathsFromPublicPath(c, natType, answer.NATType)
		if len(paths) == 0 {
			return false
		}
		natCp = append(natCp, paths...)
		return true
	})

	/*for _, cPath := range cp {
		if cPath.RemoteIP.IsPrivate() {
			//pc.opts.Logger.Infof("PRIVATE CONNECT PATH: %v", cPath)
			continue
		}
		if cPath.LocalNet.Contains(cPath.RemoteIP) {
			continue
		}
		//pc.opts.Logger.Infof("PUBLIC CONNECT PATH: %v", cPath)
		pc.generateNATConnectPathsFromPublicPath(cPath, natType, 1)
	}*/

	cp = append(cp, natCp...)

	// Here we calculate the clock offset with the target machine.
	// It is exactly what the NTP protocol does.
	//     clock offset = ((T2-T1)+(T3-T4))/2
	// T1/T4 are client send/recv; T2/T3 are server recv/send.

	T1 := offer.Timestamp[0]
	T2 := answer.Timestamp[0]
	T3 := answer.Timestamp[1]
	T4 := offer.Timestamp[1]

	// print all Ts to trace log
	pc.opts.Logger.Tracef("ICE: T1=%v, T2=%v, T3=%v, T4=%v",
		T1,
		T2,
		T3,
		T4,
	)

	clockOffset := ((T2 - T1) + (T3 - T4)) / 2

	pc.opts.Logger.Tracef("ICE: clock offset with target: %s", (time.Duration(clockOffset) * time.Millisecond).String())

	//pc.opts.Logger.Tracef("ICE: current time on server: %s", time.Now().Add(time.Duration(clockOffset)*time.Millisecond))
	//pc.opts.Logger.Tracef("ICE: current time on client: %s", time.Now())

	oneWayLatency := time.Duration(T4-(T3-clockOffset)) * time.Millisecond
	pc.opts.Logger.Tracef("ICE: one-way latency: %s", oneWayLatency)

	// adjust the connect offset to the one-way latency
	// this way we should be more accurate in case we need a further attempt
	pc.SetConnectOffset(oneWayLatency)

	scheduledAt = time.UnixMilli(answer.Timestamp[1] - clockOffset).Add(offer.ConnectOffsetDuration)

	//pc.opts.Logger.Tracef("ICE: scheduled at: %s", scheduledAt)

	return
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
	// generate 150 random ints in the range 1025-65535
	// do not allow duplicates
	ports := make(map[int]struct{})
	for i := 0; i < 150; i++ {
		p, _ := rand.Int(rand.Reader, big.NewInt(65535-1025+1))
		port := int(p.Int64()) + 1025
		if _, ok := ports[port]; ok {
			i--
			continue
		}
		ports[port] = struct{}{}
	}
	if ourNatType == int(stun.MappingEndpointIndependent) {
		// our NAT type is endpoint independent
		for port := range ports {
			addPath := *cp
			addPath.RemoteAddr = AddressFrom(addPath.Protocol.Network, cp.RemoteIP, port)
			//pc.opts.Logger.Infof("NAT CONNECT PATH: %v", addPath)
			paths = append(paths, &addPath)
		}
		return paths
	}
	// our NAT type is either address dependent or address and port dependent
	for port := range ports {
		addPath := *cp
		addPath.LocalAddr = AddressFrom(addPath.Protocol.Network, cp.LocalNet.IP, port)
		paths = append(paths, &addPath)
	}
	return paths
}
