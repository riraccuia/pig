package signaling

import (
	"context"
	"fmt"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/riraccuia/pig/pkg/ice/message"
)

// Signaler handles ICE signaling operations
type Signaler struct {
	ctx          context.Context
	opts         *Options
	mqttClient   mqtt.Client
	mqttLostConn chan struct{}
}

// NewSignaler creates a new signaler instance
func NewSignaler(ctx context.Context, opts *Options) (*Signaler, error) {
	if opts == nil {
		return nil, fmt.Errorf("Options not set")
	}

	if opts.STUNServer == "" {
		return nil, fmt.Errorf("STUN server is not set")
	}

	s := &Signaler{
		ctx:  ctx,
		opts: opts,
	}

	// Create and connect MQTT client
	client, err := s.connectMQTTClient()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MQTT broker %s: %w", opts.BrokerURL, err)
	}

	s.mqttClient = client
	s.mqttLostConn = make(chan struct{})

	return s, nil
}

// GatherICECandidates performs a STUN query, publishes an offer, and waits for an answer
func GatherICECandidates(ctx context.Context, opts *Options, targetHost string, offer *message.ICEMessage) (answer *message.ICEMessage, err error) {
	signaler, err := NewSignaler(ctx, opts)
	defer signaler.Disconnect()
	if err != nil {
		return nil, err
	}
	return signaler.GatherICECandidates(targetHost, offer)
}

// GatherICECandidates performs a STUN query, publishes an offer, and waits for an answer
func (s *Signaler) GatherICECandidates(targetHost string, offer *message.ICEMessage) (answer *message.ICEMessage, err error) {
	topicBase := s.getTopicPrefix(targetHost) + "/"
	err = s.publishICEOffer(topicBase, offer)
	if err != nil {
		return nil, err
	}
	// Wait for answer
	return s.waitForAnswer(topicBase, offer.SessionID)
}

func (s *Signaler) GetOptions() *Options {
	return s.opts
}

func (s *Signaler) Disconnect() {
	if s.mqttClient == nil {
		return
	}
	s.mqttClient.Disconnect(250)
}
