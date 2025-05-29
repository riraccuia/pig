package signaling

import (
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/riraccuia/pig/pkg/ice/message"
)

// preparePayload marshals and optionally encrypts the ICE message
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
