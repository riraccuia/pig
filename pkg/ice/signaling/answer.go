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

func (s *Signaler) SendICEAnswer(topicBase string, iceMsg *message.ICEMessage, candidates []message.ICECandidate) (answer *message.ICEMessage, err error) {
	// Create an ICE answer message
	answer, err = message.GenerateICEAnswer(candidates)
	if err != nil {
		if s.opts.Logger != nil {
			s.opts.Logger.Errorf("SIG: failed to generate ICE answer: %v", err)
		}
		return
	}

	answer.SessionID = iceMsg.SessionID

	var payload []byte
	payload, err = s.preparePayload(answer)
	if err != nil {
		if s.opts.Logger != nil {
			s.opts.Logger.Errorf("SIG: failed to prepare payload: %v", err)
		}
		return
	}

	// Publish to the answer topic
	topic := topicBase + iceMsg.SessionID + "/answer/"
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

func (s *Signaler) ReceiveICEOffers(ctx context.Context) (offersChan <-chan *message.ICEMessage, topicBase string, err error) {
	// Perform STUN query to get our public IP
	var mappedIP net.IP
	mappedIP, _, err = stun.QueryServerUDP(s.opts.Logger, s.opts.STUNServer, 0)
	if err != nil {
		if s.opts.Logger != nil {
			s.opts.Logger.Errorf("SIG: STUN query failed: %v", err)
		}
		return nil, "", err
	}

	topicBase = s.getTopicPrefix(mappedIP.String()) + "/"
	ch := make(chan *message.ICEMessage)

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

func (s *Signaler) getICEOfferHandler(ch chan *message.ICEMessage) func(client mqtt.Client, msg mqtt.Message) {
	return func(client mqtt.Client, msg mqtt.Message) {
		iceMsg, err := s.handleOfferMessage(msg.Payload())
		if err != nil {
			s.opts.Logger.Errorf("SIG: failed to handle offer message: %w", err)
			return
		}
		ch <- iceMsg
	}
}

// handleOfferMessage decrypts and validates an ICE message
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

// waitForAnswer subscribes to the answer topic and waits for a response
func (s *Signaler) waitForAnswer(topicBase, sessionID string) (answer *message.ICEMessage, err error) {
	iceMsgChan := make(chan *message.ICEMessage)

	// Subscribe to answer topic
	answerTopic := topicBase + sessionID + "/answer/#"
	if s.opts.Logger != nil {
		s.opts.Logger.Tracef("SIG: answer topic: %s", answerTopic)
	}

	if token := s.mqttClient.Subscribe(answerTopic, 0, func(client mqtt.Client, msg mqtt.Message) {
		s.handleAnswerMessage(msg, iceMsgChan)
	}); token.Wait() && token.Error() != nil {
		return nil, fmt.Errorf("failed to subscribe to ICE answer: %w", token.Error())
	}

	// Wait for answer or timeout
	select {
	case answer = <-iceMsgChan:
		if answer.SessionID != sessionID {
			err = fmt.Errorf("received ICE answer for different session: %s", answer.SessionID)
			break
		}
	case <-time.After(3 * time.Second):
		err = fmt.Errorf("timeout waiting for ICE answer")
	case <-s.ctx.Done():
		err = s.ctx.Err()
	}

	s.mqttClient.Unsubscribe(answerTopic)

	return answer, err
}

// handleAnswerMessage processes an answer message from MQTT
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
