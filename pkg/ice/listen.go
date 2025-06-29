package ice

import (
	"context"
	"errors"
	"net"
	"slices"
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
				opts.Logger.Errorf("MQTT connection failed (will retry in 5 seconds): %v", err)
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
				signaler.GetOptions().Logger.Errorf("Stopped waiting for ICE offers: %v", err)
				return
			case offer, ok := <-offersChan:
				if !ok {
					offersChan = nil
					break
				}
				signaler.GetOptions().Logger.Debugf("Received ICE offer. SessionID: %s", offer.SessionID)
				processOffer(signaler, topicBase, offer, listenPort, listenPaths, pigProtos)
			}
		}
	}
}

func processOffer(signaler *signaling.Signaler, topicBase string, offer *message.ICEMessage, listenPort uint16, listenPaths chan []*ConnectPath, pigProtos []transport.ICEProtocolDefinition) {
	localNets, localIps, err := getLocalNetworks()
	if err != nil {
		return
	}

	var (
		answerCandidates []message.ICECandidate
		cp               []*ConnectPath
		opts             = signaler.GetOptions()
	)

	for _, tr := range pigProtos {
		// local candidates
		for i, localIp := range localIps {
			bindAgent := stun.NewIceBindingAgent(opts.Logger, nil)
			cp = append(cp, &ConnectPath{
				LocalNet:  localNets[i],
				LocalAddr: AddressFrom(tr.Network, localIp, int(listenPort)),
				Protocol:  tr,
				BindAgent: bindAgent,
			})
			candidate := CandidateFrom(tr.Network, tr.ComponentID, localIp, int(listenPort))
			answerCandidates = append(answerCandidates, candidate)
			bindAgent.Ice = &stun.IceAttributes{
				Priority:      candidate.Priority,
				IceControlled: 0x12345678,
			}
		}
		// reflexive candidate
		localAddr := AddressFrom(tr.Network, net.IPv4zero, int(listenPort))
		// Get mapped endpoint
		mappedIP, mappedPort, err := PerformSTUNQuery(opts.Logger, opts.STUNServer, localAddr)
		if err != nil {
			opts.Logger.Errorf("STUN query failed: %v", err)
			continue
		}

		bindAgent := stun.NewIceBindingAgent(opts.Logger, nil)
		cp = append(cp, &ConnectPath{
			LocalAddr: localAddr,
			Protocol:  tr,
			BindAgent: bindAgent,
		})
		candidate := CandidateFrom(tr.Network, tr.ComponentID, mappedIP, mappedPort)
		answerCandidates = append(answerCandidates, candidate)
		bindAgent.Ice = &stun.IceAttributes{
			Priority:      candidate.Priority,
			IceControlled: 0x12345678,
		}
	}

	opts.Logger.Debugf("Preparing to send ICE answer to client. SessionID: %s", offer.SessionID)

	var answer *message.ICEMessage
	answer, err = signaler.SendICEAnswer(topicBase, offer, answerCandidates)
	if err != nil {
		opts.Logger.Errorf("Failed to send ICE answer: %v", err)
		return
	}

	iceAuth := &stun.StunAuthConfig{
		Username:     answer.Credentials.Username,
		Password:     answer.Credentials.Password,
		PeerUsername: offer.Credentials.Username,
		PeerPassword: offer.Credentials.Password,
	}

	for _, candidate := range offer.Candidates {
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

	select {
	case listenPaths <- cp:
	default:
	}
}
