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
	"time"

	"github.com/riraccuia/pig/pkg/ice/message"
)

func (s *Signaler) publishICEOffer(topicBase string, iceMsg *message.ICEMessage) error {
	// Create topic for offer
	offerTopic := topicBase + iceMsg.SessionID + "/offer"

	if s.opts.Logger != nil {
		s.opts.Logger.Tracef("SIG: offer topic: %s", offerTopic)
	}

	iceMsg.Timestamp[0] = time.Now().UnixMilli() // T1: client departure time of the offer

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
