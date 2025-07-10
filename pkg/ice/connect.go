package ice

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"slices"

	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/stun"
	"github.com/riraccuia/pig/pkg/transport"
)

func GetConnectPaths(ctx context.Context, opts *signaling.Options, addr string, pigProtos []transport.ICEProtocolDefinition) (cp []*ConnectPath, err error) {
	localNets, localIps, err := GetLocalNetworks()
	if err != nil {
		return nil, err
	}

	var offerCandidates []message.ICECandidate

	for _, tr := range pigProtos {
		// local candidates
		for i, localIp := range localIps {
			bindAgent := stun.NewIceBindingAgent(opts.Logger, nil)
			srcPort := rand.Intn(65535-1024) + 1024
			localAddr := AddressFrom(tr.Network, localIp, srcPort)
			cp = append(cp, &ConnectPath{
				LocalNet:  localNets[i],
				LocalAddr: localAddr,
				Protocol:  tr,
				BindAgent: bindAgent,
			})
			candidate := CandidateFrom(tr.Network, tr.ComponentID, localIp, srcPort)
			offerCandidates = append(offerCandidates, candidate)
			bindAgent.Ice = &stun.IceAttributes{
				Priority:       candidate.Priority,
				IceControlling: 0x12345678,
			}
		}
		// reflexive candidate
		localAddr := AddressFrom(tr.Network, net.IPv4zero, 0)
		// Get mapped endpoint
		mappedIP, mappedPort, err := PerformSTUNQuery(opts.Logger, opts.STUNServer, localAddr)
		if err != nil {
			return nil, fmt.Errorf("STUN query failed: %w", err)
		}
		bindAgent := stun.NewIceBindingAgent(opts.Logger, nil)
		cp = append(cp, &ConnectPath{
			LocalAddr: localAddr,
			Protocol:  tr,
			BindAgent: bindAgent,
		})
		candidate := CandidateFrom(tr.Network, tr.ComponentID, mappedIP, mappedPort)
		offerCandidates = append(offerCandidates, candidate)
		bindAgent.Ice = &stun.IceAttributes{
			Priority:       candidate.Priority,
			IceControlling: 0x12345678,
		}
	}

	var (
		offer, answer *message.ICEMessage
	)

	offer, err = message.GenerateICEOffer(offerCandidates)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ICE offer: %w", err)
	}

	answer, err = signaling.GatherICECandidates(ctx, opts, addr, offer)
	if err != nil {
		return
	}

	opts.Logger.Tracef("ICE: raw candidates from answer: %v", answer.Candidates)

	iceAuth := &stun.StunAuthConfig{
		Username:     offer.Credentials.Username,
		Password:     offer.Credentials.Password,
		PeerUsername: answer.Credentials.Username,
		PeerPassword: answer.Credentials.Password,
	}

	for _, candidate := range answer.Candidates {
		targetIP := net.ParseIP(candidate.Address)
		for _, connect := range cp {
			if connect.Protocol.Network != candidate.Protocol {
				continue
			}
			if connect.Protocol.ComponentID != candidate.ComponentID {
				continue
			}
			if connect.LocalNet != nil && !connect.LocalNet.Contains(targetIP) {
				continue
			}
			connect.ICEID = answer.SessionID
			connect.RemoteAddr = AddressFrom(connect.Protocol.Network, targetIP, candidate.Port)
			connect.BindAgent.Auth = iceAuth
		}
	}

	// remove from the connectMap the ones that do not have a remote address
	cp = slices.DeleteFunc(cp, func(c *ConnectPath) bool {
		return c.RemoteAddr == nil
	})

	opts.Logger.Tracef("ICE: connect paths: %v", cp)

	if len(cp) == 0 {
		err = fmt.Errorf("no valid candidates found")
		return
	}

	return
}
