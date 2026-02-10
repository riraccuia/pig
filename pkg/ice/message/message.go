package message

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"time"
)

// ICEMessageType defines the type of ICE message
type ICEMessageType string

const (
	// ICEMessageTypeOffer indicates an offer message from the client
	ICEMessageTypeOffer ICEMessageType = "offer"

	// ICEMessageTypeAnswer indicates an answer message from the server
	ICEMessageTypeAnswer ICEMessageType = "answer"
)

// ICECandidateType defines the type of ICE candidate
type ICECandidateType string

const (
	// ICECandidateTypeHost indicates a host candidate (local address)
	ICECandidateTypeHost ICECandidateType = "host"

	// ICECandidateTypeSrflx indicates a server reflexive candidate (from STUN)
	ICECandidateTypeSrflx ICECandidateType = "srflx"
)

// ICEMessage represents an ICE protocol message
type ICEMessage struct {
	// SessionID is the ID of the session
	SessionID string `json:"session_id"`

	// Type of the message (offer, answer, candidate)
	Type ICEMessageType `json:"type"`

	// Timestamp of when the message was created
	Timestamp int64 `json:"timestamp"`

	// ConnectOffsetDuration represents the duration that will be added to the
	// timestamp of the answer to make it the scheduled time. The value for this
	// field is elapsed time between two instants as an int64 nanosecond count.
	// This field is controlled by the offer message and must not be present in
	// the answer message.
	ConnectOffsetDuration time.Duration `json:"connect_offset_duration,omitempty"`

	// Candidates for this message
	Candidates []ICECandidate `json:"candidates"`

	// Credentials for authentication
	Credentials ICECredentials `json:"credentials"`
}

// ICECandidate represents an ICE candidate
type ICECandidate struct {
	// Foundation is a unique identifier for the candidate
	Foundation string `json:"foundation"`

	// Component ID of the candidate
	ComponentID int `json:"componentId"`

	// Priority of the candidate (higher is better)
	Priority uint32 `json:"priority"`

	// Protocol (udp, tcp)
	Protocol string `json:"protocol"`

	// Address of the candidate
	Address string `json:"address"`

	// Port of the candidate
	Port int `json:"port"`

	// Type of the candidate (host, srflx)
	Type ICECandidateType `json:"type"`

	// RelatedAddress for derived candidates (like srflx)
	RelatedAddr string `json:"relatedAddr,omitempty"`

	// RelatedPort for derived candidates
	RelatedPort int `json:"relatedPort,omitempty"`
}

// ICECredentials contains authentication information
type ICECredentials struct {
	// Username for ICE authentication
	Username string `json:"username"`

	// Password for ICE authentication
	Password string `json:"password"`
}

// GenerateICEOffer creates an ICE offer message with host and STUN-derived candidates
func GenerateICEOffer(candidates []ICECandidate) (*ICEMessage, error) {
	// Create the message
	message := &ICEMessage{
		Type:        ICEMessageTypeOffer,
		Timestamp:   time.Now().UnixMilli(),
		Candidates:  candidates,
		Credentials: generateCredentials(),
	}

	message.GenerateSessionID()

	return message, nil
}

// GenerateICEAnswer creates an ICE answer message with host and STUN-derived candidates
func GenerateICEAnswer(candidates []ICECandidate) (*ICEMessage, error) {
	message := &ICEMessage{
		Type:        ICEMessageTypeAnswer,
		Timestamp:   time.Now().UnixMilli(),
		Candidates:  candidates,
		Credentials: generateCredentials(),
	}

	return message, nil
}

func (msg *ICEMessage) GenerateSessionID() {
	msg.SessionID = RandStringFromRunes(12, az09Runes)
}

func (msg *ICEMessage) String() string {
	msgStr, _ := json.MarshalIndent(msg, "", "  ")
	return string(msgStr)
}

// Helper functions

// GenerateFoundation creates a unique foundation string for the candidate
func GenerateFoundation(addr string) string {
	hash := sha256.Sum256([]byte(addr))
	return base64.StdEncoding.EncodeToString(hash[:8])[:8] // First 8 chars of hash
}

// generateCredentials creates ICE credentials from the encryption key
func generateCredentials() ICECredentials {
	// Create a random username
	username := RandStringFromRunes(12, az09Runes)
	// Create a random password
	password := RandStringFromRunes(12, allRunes)

	return ICECredentials{
		Username: username,
		Password: password,
	}
}

var (
	az09Runes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	specRunes = []rune(",;:!?.^%+-=_#@")
	allRunes  = append(az09Runes, specRunes...)
)

func RandStringFromRunes(n int, runes []rune) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = runes[rand.Intn(len(runes))]
	}
	return string(b)
}
