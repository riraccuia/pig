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
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/stun"
	"github.com/riraccuia/pig/pkg/transport"
)

func CandidateFrom(network string, componentID int, ip net.IP, srcPort int, isReflexive bool) message.ICECandidate {
	cType := message.ICECandidateTypeHost
	cPriority := candidatePriority(network, cType, componentID, 0)
	if isReflexive {
		cType = message.ICECandidateTypeSrflx
		cPriority = candidatePriority(network, cType, componentID, 0)
	}
	return message.ICECandidate{
		Foundation:  message.GenerateFoundation(ip.String()),
		ComponentID: componentID,
		Priority:    cPriority,
		Protocol:    network,
		Address:     ip.String(),
		Port:        srcPort,
		Type:        cType,
	}
}

func candidatePriority(network string, cType message.ICECandidateType, componentID int, interfaceWeight uint16) uint32 {
	typePref := typePreference(cType)
	localPref := uint16(interfaceWeight<<8) | protoWeight(network)
	component := uint32(256 - componentID)
	return (uint32(typePref) << 24) | (uint32(localPref) << 8) | component
}

func typePreference(cType message.ICECandidateType) uint8 {
	switch cType {
	case message.ICECandidateTypeHost:
		return 126
	case message.ICECandidateTypeSrflx:
		return 100
	default:
		return 0
	}
}

func protoWeight(network string) uint16 {
	switch network {
	case "udp":
		return 200
	case "tcp":
		return 100
	default:
		return 0
	}
}

type localCandidateKey struct {
	network     string
	componentID int
	ip          string
}

type localCandidateInfo struct {
	port     int
	priority uint32
}

func makeLocalCandidateKey(tr transport.ICEProtocolDefinition, ip net.IP) localCandidateKey {
	return localCandidateKey{
		network:     tr.Network,
		componentID: tr.ComponentID,
		ip:          ip.String(),
	}
}

func buildLocalCandidates(pigProtos []transport.ICEProtocolDefinition, localEndpoints []LocalEndpoint, listenPort uint16) ([]message.ICECandidate, map[localCandidateKey]localCandidateInfo) {
	var candidates []message.ICECandidate
	localInfo := make(map[localCandidateKey]localCandidateInfo)

	for _, tr := range pigProtos {
		for _, localEndpoint := range localEndpoints {
			if tr.Network == transport.ICEProtocolTLSInICMP.Network && localEndpoint.IP.To4() == nil {
				// skip IPv6 addresses for TLS-in-ICMP
				continue
			}
			port := int(listenPort)
			if port == 0 {
				port = randomPort()
			}
			candidate := CandidateFrom(tr.Network, tr.ComponentID, localEndpoint.IP, port, false)
			key := makeLocalCandidateKey(tr, localEndpoint.IP)
			localInfo[key] = localCandidateInfo{
				port:     port,
				priority: candidate.Priority,
			}
			candidates = append(candidates, candidate)
		}
	}
	return candidates, localInfo
}

func buildReflexiveCandidates(pigProtos []transport.ICEProtocolDefinition, localEndpoints []LocalEndpoint, localInfo map[localCandidateKey]localCandidateInfo, opts *signaling.Options) []message.ICECandidate {
	type ipPort struct {
		ip   net.IP
		port int
	}
	var (
		candidates  []message.ICECandidate
		mappedAddrs = make(map[string]ipPort)
		stunClient  = stun.NewClient(
			opts.STUNServer,
		).WithDialer(
			network.NewDialer(time.Second * 5),
		).WithLoggerFunc(
			opts.Logger.PrintLevel,
		)
	)

	for _, tr := range pigProtos {
		for _, localEndpoint := range localEndpoints {
			if tr.Network == transport.ICEProtocolTLSInICMP.Network && localEndpoint.IP.To4() == nil {
				// skip IPv6 addresses for TLS-in-ICMP
				continue
			}
			info, ok := localInfo[makeLocalCandidateKey(tr, localEndpoint.IP)]
			if !ok {
				continue
			}
			family := getFamilyForIP(localEndpoint.IP)
			mappingKey := fmt.Sprintf("%d:%s:%d", family, tr.Network, info.port)
			ma, ok := mappedAddrs[mappingKey]
			if ok {
				candidates = append(candidates, CandidateFrom(tr.Network, tr.ComponentID, ma.ip, ma.port, true))
				continue
			}
			opts.Logger.Tracef("ICE: performing STUN query for %d:%s:%s:%d", family, tr.Network, localEndpoint.IP.String(), info.port)
			mappedIP, mappedPort, err := PerformSTUNQuery(stunClient, AddressFrom(tr.Network, localEndpoint.IP, info.port))
			if err != nil {
				opts.Logger.Errorf("ICE: STUN query failed: %v", err)
				continue
			}
			opts.Logger.Tracef("ICE: STUN query successful | %d:%s:%s:%d -> %s:%d", family, tr.Network, localEndpoint.IP.String(), info.port, mappedIP.String(), mappedPort)
			mappedAddrs[mappingKey] = ipPort{ip: mappedIP, port: mappedPort}
			candidates = append(candidates, CandidateFrom(tr.Network, tr.ComponentID, mappedIP, mappedPort, true))
		}
	}

	return candidates
}

func randomPort() int {
	return rand.Intn(65535-1024) + 1024
}
