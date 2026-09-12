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
	"errors"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/stun"
)

type OfferPaths struct {
	ScheduledAt  time.Time
	ConnectPaths []*ConnectPath
}

func (pc *PathConnector) GetListenPaths(ctx context.Context, listenPort uint16) (chan *OfferPaths, error) {
	var (
		err error
	)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
			pc.signaler, err = signaling.NewSignaler(ctx, pc.opts)
		}
		if errors.Is(err, signaling.ErrMQTTFailure) {
			if pc.opts.Logger != nil {
				pc.opts.Logger.Errorf("ICE: MQTT connection failed (will retry in 5 seconds): %v", err)
			}
			time.Sleep(time.Second * 5)
			continue
		}
		break
	}
	listenPaths := make(chan *OfferPaths, 10)
	go pc.receiveOffers(ctx, listenPort, listenPaths)
	return listenPaths, nil
}

func (pc *PathConnector) receiveOffers(ctx context.Context, listenPort uint16, listenPaths chan *OfferPaths) {
	var (
		err        error
		offersChan <-chan *signaling.ReceivedOffer
		topicBase  string
	)
	for {
		if offersChan == nil {
			offersChan, topicBase, err = pc.signaler.ReceiveICEOffers(ctx)
		}
		if err != nil {
			time.Sleep(time.Second * 5)
			continue
		}
		for offersChan != nil {
			select {
			case <-ctx.Done():
				err = ctx.Err()
				pc.opts.Logger.Errorf("ICE: stopped waiting for ICE offers: %v", err)
				return
			case offer, ok := <-offersChan:
				if !ok {
					offersChan = nil
					break
				}
				pc.opts.Logger.Tracef("ICE: received ICE offer. SessionID: %s", offer.Offer.SessionID)
				pc.processOffer(topicBase, offer, listenPort, listenPaths)
			}
		}
	}
}

func (pc *PathConnector) processOffer(topicBase string, offer *signaling.ReceivedOffer, listenPort uint16, listenPaths chan *OfferPaths) {
	localEndpoints, err := GetLocalEndpoints("", pc.excludedAdapters)
	if err != nil {
		return
	}

	// NAT behavior can change over time or under certain conditions, so we need to discover it again for each new negotiation
	natType := pc.discoverNATType()

	var (
		answerCandidates []message.ICECandidate
		localInfo        map[localCandidateKey]localCandidateInfo
		connectPaths     []*ConnectPath
	)

	answerCandidates, localInfo = buildLocalCandidates(pc.pigProtos, localEndpoints, listenPort)
	answerCandidates = append(answerCandidates, buildReflexiveCandidates(pc.pigProtos, localEndpoints, localInfo, pc.opts)...)
	answerCandidates = dedupCandidates(answerCandidates)

	pc.opts.Logger.Tracef("ICE: preparing to send ICE answer to client. SessionID: %s", offer.Offer.SessionID)

	var answer *message.ICEMessage

	// Create the ICE answer message
	answer, err = message.GenerateICEMessage(message.ICEMessageTypeAnswer, answerCandidates)
	if err != nil {
		pc.opts.Logger.Errorf("ICE: failed to generate ICE answer: %v", err)
		return
	}

	answer.Timestamp[0] = offer.ArrivalTime // T2: server arrival time of the request

	answer.NATType = natType

	err = pc.signaler.SendICEAnswer(topicBase, offer.Offer, answer)
	if err != nil {
		pc.opts.Logger.Errorf("ICE: failed to send ICE answer: %v", err)
		return
	}

	iceAuth := &stun.IceAuth{
		LocalUfrag:     answer.Credentials.Username,
		LocalPassword:  answer.Credentials.Password,
		RemoteUfrag:    offer.Offer.Credentials.Username,
		RemotePassword: offer.Offer.Credentials.Password,
	}
	var bindLogger stun.LoggerFunc
	if pc.opts.Logger != nil {
		bindLogger = pc.opts.Logger.PrintLevel
	}

	pc.opts.Logger.Tracef("ICE: raw candidates from offer: %v", offer.Offer.Candidates)

	for _, candidate := range offer.Offer.Candidates {
		targetIP := net.ParseIP(candidate.Address)
		for _, tr := range pc.pigProtos {
			if tr.Network != candidate.Protocol {
				continue
			}
			if tr.ComponentID != candidate.ComponentID {
				continue
			}
			for _, localEndpoint := range localEndpoints {
				localNet := localEndpoint.Net
				if getFamilyForIP(localEndpoint.IP) != getFamilyForIP(targetIP) {
					continue
				}
				if candidate.Type == message.ICECandidateTypeHost && localNet != nil && localNet.IP.IsPrivate() && !localNet.Contains(targetIP) {
					continue
				}
				info, ok := localInfo[makeLocalCandidateKey(tr, localEndpoint.IP)]
				if !ok {
					continue
				}
				cPath := getPathForProto(tr, localNet, localEndpoint.IP, nil, uint16(info.port))
				cPath.BindAgent = stun.NewBindingAgent(stun.NewControlledICEBindingAgentConfig(bindLogger, iceAuth, info.priority))
				cPath.ICEID = answer.SessionID
				cPath.RemoteAddr = AddressFrom(cPath.Protocol.Network, targetIP, candidate.Port)
				cPath.RemoteIP = targetIP
				//cPath.ScheduledAt = time.UnixMilli(answer.Timestamp).Add(offer.ConnectOffsetDuration)
				connectPaths = append(connectPaths, cPath)
			}
		}
	}
	connectPaths = dedupConnectPaths(connectPaths)
	connectPaths = sortConnectPaths(connectPaths)

	// send the connect paths to the listener
	select {
	case listenPaths <- &OfferPaths{ConnectPaths: connectPaths, ScheduledAt: time.UnixMilli(answer.Timestamp[1]).Add(offer.Offer.ConnectOffsetDuration)}:
	default:
	}
}
