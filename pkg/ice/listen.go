package ice

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/stun"
	"github.com/riraccuia/pig/pkg/transport"
)

func GetListenPaths(ctx context.Context, opts *signaling.Options, listenPort uint16, pigProtos []transport.ICEProtocolDefinition) (chan []*ConnectPath, error) {
	var (
		signaler *signaling.Signaler
		err      error
	)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			signaler, err = signaling.NewSignaler(ctx, opts)
		}
		if errors.Is(err, signaling.ErrMQTTFailure) {
			if opts.Logger != nil {
				opts.Logger.Errorf("ICE: MQTT connection failed (will retry in 5 seconds): %v", err)
			}
			time.Sleep(time.Second * 5)
			continue
		}
		break
	}
	listenPaths := make(chan []*ConnectPath, 10)
	go receiveOffers(ctx, signaler, listenPort, listenPaths, pigProtos)
	return listenPaths, nil
}

func receiveOffers(ctx context.Context, signaler *signaling.Signaler, listenPort uint16, listenPaths chan []*ConnectPath, pigProtos []transport.ICEProtocolDefinition) {
	var (
		err        error
		offersChan <-chan *message.ICEMessage
		topicBase  string
	)
	for {
		if offersChan == nil {
			offersChan, topicBase, err = signaler.ReceiveICEOffers(ctx)
		}
		if err != nil {
			time.Sleep(time.Second * 5)
			continue
		}
		for offersChan != nil {
			select {
			case <-ctx.Done():
				err = ctx.Err()
				signaler.GetOptions().Logger.Errorf("ICE: stopped waiting for ICE offers: %v", err)
				return
			case offer, ok := <-offersChan:
				if !ok {
					offersChan = nil
					break
				}
				signaler.GetOptions().Logger.Tracef("ICE: received ICE offer. SessionID: %s", offer.SessionID)
				processOffer(signaler, topicBase, offer, listenPort, listenPaths, pigProtos)
			}
		}
	}
}

func processOffer(signaler *signaling.Signaler, topicBase string, offer *message.ICEMessage, listenPort uint16, listenPaths chan []*ConnectPath, pigProtos []transport.ICEProtocolDefinition) {
	localNets, localIps, err := GetLocalNetworks("")
	if err != nil {
		return
	}

	var (
		answerCandidates []message.ICECandidate
		connectPaths     []*ConnectPath
		opts             = signaler.GetOptions()
	)

	var localInfo map[localCandidateKey]localCandidateInfo
	answerCandidates, localInfo = buildLocalCandidates(pigProtos, localIps, listenPort)
	answerCandidates = append(answerCandidates, buildReflexiveCandidates(pigProtos, localIps, localInfo, opts)...)
	answerCandidates = dedupCandidates(answerCandidates)

	opts.Logger.Tracef("ICE: preparing to send ICE answer to client. SessionID: %s", offer.SessionID)

	var answer *message.ICEMessage
	answer, err = signaler.SendICEAnswer(topicBase, offer, answerCandidates)
	if err != nil {
		opts.Logger.Errorf("ICE: failed to send ICE answer: %v", err)
		return
	}

	iceAuth := &stun.StunAuthConfig{
		Username:     answer.Credentials.Username,
		Password:     answer.Credentials.Password,
		PeerUsername: offer.Credentials.Username,
		PeerPassword: offer.Credentials.Password,
	}

	opts.Logger.Tracef("ICE: raw candidates from offer: %v", offer.Candidates)

	for _, candidate := range offer.Candidates {
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
				cPath := getPathForProto(tr, localNet, localIP, nil, uint16(info.port), opts)
				cPath.BindAgent.SetControlled(iceAuth, info.priority)
				cPath.ICEID = answer.SessionID
				cPath.RemoteAddr = AddressFrom(cPath.Protocol.Network, targetIP, candidate.Port)
				cPath.ScheduledAt = time.UnixMilli(answer.Timestamp).Add(offer.ConnectOffsetDuration)
				connectPaths = append(connectPaths, cPath)
			}
		}
	}
	connectPaths = dedupConnectPaths(connectPaths)
	// send the connect paths to the listener
	select {
	case listenPaths <- connectPaths:
	default:
	}
}
