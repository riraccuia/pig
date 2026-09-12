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

package signaling

import (
	"context"
	"fmt"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/stun"
)

// Signaler handles ICE signaling operations.
type Signaler struct {
	ctx          context.Context
	opts         *Options
	stunClient   *stun.Client
	mqttClient   mqtt.Client
	mqttLostConn chan struct{}
}

// NewSignaler creates a new signaler instance.
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

	s.stunClient = stun.NewClient(
		opts.STUNServer,
	).WithDialer(
		network.NewDialer(time.Second * 5),
	).WithLoggerFunc(
		opts.Logger.PrintLevel,
	)

	// Create and connect MQTT client
	client, err := s.connectMQTTClient()
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MQTT broker %s: %w", opts.BrokerURL, err)
	}

	s.mqttClient = client
	s.mqttLostConn = make(chan struct{})

	return s, nil
}

// GatherICECandidates performs a STUN query, publishes an offer, and waits for an answer.
func GatherICECandidates(ctx context.Context, opts *Options, targetHost string, offer *message.ICEMessage) (answer *message.ICEMessage, err error) {
	signaler, err := NewSignaler(ctx, opts)
	if err != nil {
		return nil, err
	}
	defer signaler.Disconnect()
	return signaler.GatherICECandidates(targetHost, offer)
}

// GatherICECandidates performs a STUN query, publishes an offer, and waits for an answer.
func (s *Signaler) GatherICECandidates(targetHost string, offer *message.ICEMessage) (answer *message.ICEMessage, err error) {
	topicBase := s.getTopicPrefix(targetHost) + "/"
	err = s.publishICEOffer(topicBase, offer)
	if err != nil {
		return nil, err
	}
	// Wait for answer
	return s.waitForAnswer(topicBase, offer)
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
