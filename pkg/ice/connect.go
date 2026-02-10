package ice

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/stun"
	"github.com/riraccuia/pig/pkg/transport"
)

func GetConnectPaths(ctx context.Context, opts *signaling.Options, target *config.Target, pigProtos []transport.ICEProtocolDefinition) (cp []*ConnectPath, err error) {
	localNets, localIps, err := GetLocalNetworks("")
	if err != nil {
		return nil, err
	}

	var offerCandidates []message.ICECandidate
	var localInfo map[localCandidateKey]localCandidateInfo

	offerCandidates, localInfo = buildLocalCandidates(pigProtos, localIps, uint16(target.SrcPort))
	offerCandidates = append(offerCandidates, buildReflexiveCandidates(pigProtos, localIps, localInfo, opts)...)
	offerCandidates = dedupCandidates(offerCandidates)

	var (
		offer, answer *message.ICEMessage
	)

	offer, err = message.GenerateICEOffer(offerCandidates)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ICE offer: %w", err)
	}

	offer.ConnectOffsetDuration = opts.ConnectOffset

	answer, err = signaling.GatherICECandidates(ctx, opts, target.Address, offer)
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
		for _, tr := range pigProtos {
			if tr.Network != candidate.Protocol {
				continue
			}
			if tr.ComponentID != candidate.ComponentID {
				continue
			}
			for i, localIP := range localIps {
				localNet := localNets[i]
				if getFamilyForIP(localIP) != getFamilyForIP(targetIP) {
					continue
				}
				if candidate.Type == message.ICECandidateTypeHost && localNet != nil && localNet.IP.IsPrivate() && !localNet.Contains(targetIP) {
					continue
				}
				info, ok := localInfo[makeLocalCandidateKey(tr, localIP)]
				if !ok {
					continue
				}
				connect := getPathForProto(tr, localNet, localIP, nil, uint16(info.port), opts)
				connect.BindAgent.SetControlling(iceAuth, info.priority)
				connect.ICEID = answer.SessionID
				connect.RemoteAddr = AddressFrom(connect.Protocol.Network, targetIP, candidate.Port)
				connect.ScheduledAt = time.UnixMilli(answer.Timestamp).Add(offer.ConnectOffsetDuration)
				cp = append(cp, connect)
			}
		}
	}
	cp = dedupConnectPaths(cp)

	opts.Logger.Tracef("ICE: connect paths: %v", cp)

	if len(cp) == 0 {
		err = fmt.Errorf("no valid candidates found")
		return
	}

	return
}
