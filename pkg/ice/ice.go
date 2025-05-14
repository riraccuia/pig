package ice

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net"
	"time"
)

// ICEMessageType defines the type of ICE message
type ICEMessageType string

const (
	// ICEMessageTypeOffer indicates an offer message from the client
	ICEMessageTypeOffer ICEMessageType = "offer"

	// ICEMessageTypeAnswer indicates an answer message from the server
	ICEMessageTypeAnswer ICEMessageType = "answer"

	// ICEMessageTypeCandidate indicates additional candidates
	ICEMessageTypeCandidate ICEMessageType = "candidate"
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
	// Type of the message (offer, answer, candidate)
	Type ICEMessageType `json:"type"`

	// Timestamp of when the message was created
	Timestamp int64 `json:"timestamp"`

	// Candidates for this message
	Candidates []ICECandidate `json:"candidates"`

	// Credentials for authentication
	Credentials ICECredentials `json:"credentials"`
}

// ICECandidate represents an ICE candidate
type ICECandidate struct {
	// Foundation is a unique identifier for the candidate
	Foundation string `json:"foundation"`

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
func GenerateICEOffer(mappedIP net.IP, mappedPort int, localAddr *net.UDPAddr, encryptionKey []byte) *ICEMessage {
	// Create the message
	message := &ICEMessage{
		Type:      ICEMessageTypeOffer,
		Timestamp: time.Now().Unix(),
		Candidates: []ICECandidate{
			// Host candidate (local address)
			{
				Foundation: generateFoundation(localAddr.String()),
				Priority:   calculateHostPriority(),
				Protocol:   "udp",
				Address:    localAddr.IP.String(),
				Port:       localAddr.Port,
				Type:       ICECandidateTypeHost,
			},
			// Server reflexive candidate (from STUN)
			{
				Foundation:  generateFoundation(mappedIP.String()),
				Priority:    calculateSrflxPriority(),
				Protocol:    "udp",
				Address:     mappedIP.String(),
				Port:        mappedPort,
				Type:        ICECandidateTypeSrflx,
				RelatedAddr: localAddr.IP.String(),
				RelatedPort: localAddr.Port,
			},
		},
		Credentials: generateCredentials(encryptionKey),
	}

	return message
}

// GenerateICEAnswer creates an ICE answer message with host and STUN-derived candidates
func GenerateICEAnswer(mappedIP net.IP, mappedPort int, localAddr *net.UDPAddr, encryptionKey []byte) *ICEMessage {
	// Create the message, similar to the offer but with different type
	message := &ICEMessage{
		Type:      ICEMessageTypeAnswer,
		Timestamp: time.Now().Unix(),
		Candidates: []ICECandidate{
			// Host candidate (local address)
			{
				Foundation: generateFoundation(localAddr.String()),
				Priority:   calculateHostPriority(),
				Protocol:   "udp",
				Address:    localAddr.IP.String(),
				Port:       localAddr.Port,
				Type:       ICECandidateTypeHost,
			},
			// Server reflexive candidate (from STUN)
			{
				Foundation:  generateFoundation(mappedIP.String()),
				Priority:    calculateSrflxPriority(),
				Protocol:    "udp",
				Address:     mappedIP.String(),
				Port:        mappedPort,
				Type:        ICECandidateTypeSrflx,
				RelatedAddr: localAddr.IP.String(),
				RelatedPort: localAddr.Port,
			},
		},
		Credentials: generateCredentials(encryptionKey),
	}

	return message
}

// GetPreferredCandidate returns the best candidate from an ICE message
// This is a simplified implementation that prioritizes srflx candidates
func GetPreferredCandidate(msg *ICEMessage) (string, int, error) {
	if msg == nil || len(msg.Candidates) == 0 {
		return "", 0, fmt.Errorf("no candidates available")
	}

	// First look for srflx candidates
	for _, candidate := range msg.Candidates {
		if candidate.Type == ICECandidateTypeSrflx {
			return candidate.Address, candidate.Port, nil
		}
	}

	// Fall back to any candidate
	candidate := msg.Candidates[0]
	return candidate.Address, candidate.Port, nil
}

func (msg *ICEMessage) String() string {
	msgStr, _ := json.MarshalIndent(msg, "", "  ")
	return string(msgStr)
}

// Helper functions

// generateFoundation creates a unique foundation string for the candidate
func generateFoundation(addr string) string {
	hash := sha256.Sum256([]byte(addr))
	return base64.StdEncoding.EncodeToString(hash[:8])[:8] // First 8 chars of hash
}

// calculateHostPriority returns the priority for host candidates
func calculateHostPriority() uint32 {
	// Per ICE RFC: type preference (126) << 24 | local preference (65535) << 8 | 255
	return (126 << 24) | (65535 << 8) | 255
}

// calculateSrflxPriority returns the priority for server reflexive candidates
func calculateSrflxPriority() uint32 {
	// Per ICE RFC: type preference (100) << 24 | local preference (65535) << 8 | 255
	return (100 << 24) | (65535 << 8) | 255
}

// generateCredentials creates ICE credentials from the encryption key
func generateCredentials(encryptionKey []byte) ICECredentials {
	// Create a random username
	username := RandStringRunes(12)
	// Create a random password
	password := RandStringRunes(12)

	return ICECredentials{
		Username: username,
		Password: password,
	}
}

var credsGenRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,;:!?.^%+-=_#@")

func RandStringRunes(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = credsGenRunes[rand.Intn(len(credsGenRunes))]
	}
	return string(b)
}
