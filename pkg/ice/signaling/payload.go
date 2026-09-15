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
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/riraccuia/pig/pkg/ice/message"
)

// preparePayload marshals and optionally encrypts the ICE message.
func (s *Signaler) preparePayload(iceMsg *message.ICEMessage) ([]byte, error) {
	// Marshal ICE message to JSON
	msgBytes, err := json.Marshal(iceMsg)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ICE message: %w", err)
	}

	payload := msgBytes

	if s.opts.EncryptionKey == nil {
		return payload, nil
	}

	// Encrypt the message
	ciphertext, err := Encrypt(msgBytes, s.opts.EncryptionKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message: %w", err)
	}
	// base64 encode the ciphertext
	ciphertextStr := base64.StdEncoding.EncodeToString(ciphertext)
	payload = []byte(ciphertextStr)

	return payload, nil
}
