package signaling

import (
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/ice/message"
)

func (s *Signaler) publishICEOffer(topicBase string, mappedIP net.IP, mappedPort int, localAddr net.Addr) (*message.ICEMessage, error) {
	// Create and publish offer
	iceMsg, err := s.createICEOffer(mappedIP, mappedPort, localAddr)
	if err != nil {
		return nil, err
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

// createICEOffer creates an ICE offer message
func (s *Signaler) createICEOffer(mappedIP net.IP, mappedPort int, localAddr net.Addr) (*message.ICEMessage, error) {
	// Create ICE offer message
	iceMsg, err := message.GenerateICEOffer(mappedIP, mappedPort, localAddr, s.opts.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ICE offer: %w", err)
	}

	return iceMsg, nil
}
