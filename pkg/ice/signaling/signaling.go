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

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/riraccuia/pig/pkg/ice/message"
)

// Signaler handles ICE signaling operations.
type Signaler struct {
	opts         *Options
	mqttClient   mqtt.Client
	mqttLostConn chan struct{}
}

// NewSignaler creates a new signaler instance.
func NewSignaler(opts *Options) (*Signaler, error) {
	if opts == nil {
		return nil, fmt.Errorf("Options not set")
	}

	s := &Signaler{
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

// GatherICECandidates performs a STUN query, publishes an offer, and waits for an answer.
func (s *Signaler) GatherICECandidates(ctx context.Context, targetHost string, offer *message.ICEMessage) (answer *message.ICEMessage, err error) {
	topicBase := s.getTopicPrefix(targetHost) + "/"
	err = s.publishICEOffer(topicBase, offer)
	if err != nil {
		return nil, err
	}
	// Wait for answer
	return s.waitForAnswer(ctx, topicBase, offer)
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
