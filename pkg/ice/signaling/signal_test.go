package signaling

import (
	"testing"

	"github.com/riraccuia/pig/pkg/ice/message"
)

// validateICEMessage validates ICE messages
func validateICEMessage(t *testing.T, iceMsg *message.ICEMessage) {
	// Validate message type
	if iceMsg.Type != message.ICEMessageTypeOffer {
		t.Errorf("Wrong message type: got %s, want %s", iceMsg.Type, message.ICEMessageTypeOffer)
	}

	// Check for required fields
	if len(iceMsg.Candidates) == 0 {
		t.Error("No candidates in ICE message")
		return
	}

	// At least one candidate should be of type srflx
	hasSrflx := false
	for _, candidate := range iceMsg.Candidates {
		if candidate.Type == message.ICECandidateTypeSrflx {
			hasSrflx = true
			// Verify server reflexive candidate
			if candidate.Address == "" {
				t.Error("Empty address in srflx candidate")
			}
			if candidate.Port == 0 {
				t.Error("Zero port in srflx candidate")
			}
		}
	}

	if !hasSrflx {
		t.Error("No server reflexive candidate found")
	}

	// Check credentials
	if iceMsg.Credentials.Username == "" {
		t.Error("Empty username in ICE credentials")
	}
	if iceMsg.Credentials.Password == "" {
		t.Error("Empty password in ICE credentials")
	}

	t.Logf("Successfully received ICE message with %d candidates", len(iceMsg.Candidates))
}
