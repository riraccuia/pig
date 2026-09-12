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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/stun"
)

func (s *Signaler) SendICEAnswer(topicBase string, offer *message.ICEMessage, answer *message.ICEMessage) (err error) {
	answer.SessionID = offer.SessionID
	answer.Timestamp[1] = time.Now().UnixMilli() // T3: server departure time of the reply

	var payload []byte
	payload, err = s.preparePayload(answer)
	if err != nil {
		if s.opts.Logger != nil {
			s.opts.Logger.Errorf("SIG: failed to prepare payload: %v", err)
		}
		return
	}

	// Publish to the answer topic
	topic := topicBase + offer.SessionID + "/answer/"
	if s.opts.Logger != nil {
		s.opts.Logger.Tracef("SIG: publishing ICE answer to topic: %s", topic)
	}

	err = s.connectAndPublish(topic, payload)
	if err != nil {
		if s.opts.Logger != nil {
			s.opts.Logger.Errorf("SIG: failed to publish ICE answer: %v", err)
		}
	}
	return
}

type ReceivedOffer struct {
	Offer       *message.ICEMessage
	ArrivalTime int64
}

func (s *Signaler) ReceiveICEOffers(ctx context.Context) (offersChan <-chan *ReceivedOffer, topicBase string, err error) {
	// Perform STUN query to get our public IP
	var result *stun.BindingResult
	result, err = s.stunClient.QueryStunServerUDP(&net.UDPAddr{IP: nil, Port: 0})
	if err != nil {
		if s.opts.Logger != nil {
			s.opts.Logger.Errorf("SIG: STUN query failed: %v", err)
		}
		return nil, "", err
	}
	mappedIP := result.IP

	topicBase = s.getTopicPrefix(mappedIP.String()) + "/"
	ch := make(chan *ReceivedOffer)

	s.opts.Logger.Tracef("SIG: receiving ICE offers from topic: %s", topicBase+"+/offer")

	err = s.connectAndSubscribe(topicBase+"+/offer", s.getICEOfferHandler(ch))
	if err != nil {
		close(ch)
		return nil, "", err
	}

	connLost := s.mqttLostConn

	go func() {
		select {
		case <-ctx.Done():
			s.mqttClient.Unsubscribe(topicBase + "+/offer")
		case <-connLost:
		}
		close(ch)
	}()

	return ch, topicBase, nil
}

func (s *Signaler) getICEOfferHandler(ch chan *ReceivedOffer) func(client mqtt.Client, msg mqtt.Message) {
	return func(client mqtt.Client, msg mqtt.Message) {
		ro := ReceivedOffer{
			ArrivalTime: time.Now().UnixMilli(), // T2: server arrival time of the request
		}
		iceMsg, err := s.handleOfferMessage(msg.Payload())
		if err != nil {
			s.opts.Logger.Errorf("SIG: failed to handle offer message: %w", err)
			return
		}
		ro.Offer = iceMsg
		ch <- &ro
	}
}

// handleOfferMessage decrypts and validates an ICE message.
func (s *Signaler) handleOfferMessage(msg []byte) (*message.ICEMessage, error) {
	var (
		payload []byte
		err     error
	)
	// s.opts.Logger.Debugf("received ICE offer message: %s", string(msg))
	if s.opts.EncryptionKey != nil {
		// Decrypt the message
		ciphertext, err := base64.StdEncoding.DecodeString(string(msg))
		if err != nil {
			return nil, fmt.Errorf("failed to decode message: %w", err)
		}

		decrypted, err := Decrypt(ciphertext, s.opts.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt message: %w", err)
		}
		payload = decrypted
	}
	// Parse the ICE message
	var iceMsg message.ICEMessage
	if err = json.Unmarshal(payload, &iceMsg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ICE message: %w", err)
	}

	return &iceMsg, nil
}

// waitForAnswer subscribes to the answer topic and waits for a response.
func (s *Signaler) waitForAnswer(topicBase string, offer *message.ICEMessage) (answer *message.ICEMessage, err error) {
	iceMsgChan := make(chan *message.ICEMessage)

	// Subscribe to answer topic
	answerTopic := topicBase + offer.SessionID + "/answer/#"
	if s.opts.Logger != nil {
		s.opts.Logger.Tracef("SIG: answer topic: %s", answerTopic)
	}

	if token := s.mqttClient.Subscribe(answerTopic, 0, func(client mqtt.Client, msg mqtt.Message) {
		offer.Timestamp[1] = time.Now().UnixMilli() // T4: client arrival time of the reply
		s.handleAnswerMessage(msg, iceMsgChan)
	}); token.Wait() && token.Error() != nil {
		return nil, fmt.Errorf("failed to subscribe to ICE answer: %w", token.Error())
	}

	// Wait for answer or timeout
	select {
	case answer = <-iceMsgChan:
		s.opts.Logger.Tracef("SIG: received ICE answer for session: %s", answer.SessionID)
		if answer.SessionID != offer.SessionID {
			err = fmt.Errorf("received ICE answer for different session: %s", answer.SessionID)
			break
		}
	case <-time.After(3 * time.Second):
		s.opts.Logger.Errorf("SIG: timeout waiting for ICE answer")
		err = fmt.Errorf("timeout waiting for ICE answer")
	case <-s.ctx.Done():
		err = s.ctx.Err()
	}

	s.mqttClient.Unsubscribe(answerTopic)

	return answer, err
}

// handleAnswerMessage processes an answer message from MQTT.
func (s *Signaler) handleAnswerMessage(msg mqtt.Message, iceMsgChan chan<- *message.ICEMessage) {
	if s.opts.Logger != nil {
		s.opts.Logger.Tracef("SIG: received ICE answer")
	}

	var (
		payload = msg.Payload()
		err     error
	)

	// Decrypt if needed
	if s.opts.EncryptionKey != nil {
		// Decrypt the message
		ciphertext, err := base64.StdEncoding.DecodeString(string(payload))
		if err != nil {
			s.opts.Logger.Errorf("SIG: failed to decode message: %w", err)
			return
		}

		decrypted, err := Decrypt(ciphertext, s.opts.EncryptionKey)
		if err != nil {
			s.opts.Logger.Errorf("SIG: failed to decrypt message: %w", err)
			return
		}
		payload = decrypted
	}

	// Parse the ICE message
	var iceMsg message.ICEMessage
	if err = json.Unmarshal(payload, &iceMsg); err != nil {
		s.opts.Logger.Errorf("SIG: failed to unmarshal ICE message: %w", err)
		return
	}

	iceMsgChan <- &iceMsg
}
