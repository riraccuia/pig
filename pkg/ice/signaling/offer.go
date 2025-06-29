package signaling

import (
	"github.com/riraccuia/pig/pkg/ice/message"
)

func (s *Signaler) publishICEOffer(topicBase string, iceMsg *message.ICEMessage) error {
	// Create topic for offer
	offerTopic := topicBase + iceMsg.SessionID + "/offer"

	if s.opts.Logger != nil {
		s.opts.Logger.Debugf("offer topic: %s", offerTopic)
	}

	// Prepare payload
	payload, err := s.preparePayload(iceMsg)
	if err != nil {
		return err
	}

	// Connect to MQTT and publish
	err = s.connectAndPublish(offerTopic, payload)
	if err != nil {
		return err
	}

	return nil
}
