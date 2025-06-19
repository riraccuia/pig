package signaling

import (
	"fmt"

	"github.com/riraccuia/pig/pkg/ice/message"
)

func (s *Signaler) publishICEOffer(topicBase string, candidates []message.ICECandidate) (*message.ICEMessage, error) {
	// Create ICE offer message
	iceMsg, err := message.GenerateICEOffer(candidates, s.opts.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ICE offer: %w", err)
	}

	// Create topic for offer
	offerTopic := topicBase + iceMsg.SessionID + "/offer"

	if s.opts.Logger != nil {
		s.opts.Logger.Debugf("offer topic: %s", offerTopic)
	}

	// Prepare payload
	payload, err := s.preparePayload(iceMsg)
	if err != nil {
		return nil, err
	}

	// Connect to MQTT and publish
	err = s.connectAndPublish(offerTopic, payload)
	if err != nil {
		return nil, err
	}

	return iceMsg, nil
}
