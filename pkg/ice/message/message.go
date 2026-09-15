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

package message

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/rand"
	"time"
)

// ICEMessageType defines the type of ICE message.
type ICEMessageType string

const (
	// ICEMessageTypeOffer indicates an offer message from the client.
	ICEMessageTypeOffer ICEMessageType = "offer"

	// ICEMessageTypeAnswer indicates an answer message from the server.
	ICEMessageTypeAnswer ICEMessageType = "answer"
)

// ICECandidateType defines the type of ICE candidate.
type ICECandidateType string

const (
	// ICECandidateTypeHost indicates a host candidate (local address).
	ICECandidateTypeHost ICECandidateType = "host"

	// ICECandidateTypeSrflx indicates a server reflexive candidate (from STUN).
	ICECandidateTypeSrflx ICECandidateType = "srflx"
)

// ICEMessage represents an ICE protocol message.
type ICEMessage struct {
	// SessionID is the ID of the session.
	SessionID string `json:"session_id"`

	// Type of the message (offer, answer, candidate).
	Type ICEMessageType `json:"type"`

	// Timestamps for clock offset calculation.
	// For an offer message:
	// [0] = T1: the time that the offer was sent
	// [1] = T4: the time that the offering side received the answer
	// For an answer message:
	// [0] = T2: the time that the offer was received
	// [1] = T3: the time that the answering side sent the answer
	Timestamp [2]int64 `json:"timestamp"`

	// ConnectOffsetDuration represents the duration that will be added to the
	// timestamp of the answer to make it the scheduled time. The value for this
	// field is elapsed time between two instants as an int64 nanosecond count.
	// This field is controlled by the offer message and must not be present in
	// the answer message.
	ConnectOffsetDuration time.Duration `json:"connect_offset_duration,omitempty"`

	// NATType represents the NAT type of the remote peer.
	// 0: endpoint-independent mapping
	// 1: address-dependent mapping
	NATType int `json:"nat_type,omitempty"`

	// Candidates for this message.
	Candidates []ICECandidate `json:"candidates"`

	// Credentials for authentication.
	Credentials ICECredentials `json:"credentials"`
}

// ICECandidate represents an ICE candidate.
type ICECandidate struct {
	// Foundation is a unique identifier for the candidate.
	Foundation string `json:"foundation"`

	// Component ID of the candidate.
	ComponentID int `json:"componentId"`

	// Priority of the candidate (higher is better).
	Priority uint32 `json:"priority"`

	// Protocol (udp, tcp).
	Protocol string `json:"protocol"`

	// Address of the candidate.
	Address string `json:"address"`

	// Port of the candidate.
	Port int `json:"port"`

	// Type of the candidate (host, srflx).
	Type ICECandidateType `json:"type"`

	// RelatedAddress for derived candidates (like srflx).
	RelatedAddr string `json:"relatedAddr,omitempty"`

	// RelatedPort for derived candidates.
	RelatedPort int `json:"relatedPort,omitempty"`
}

// ICECredentials contains authentication information.
type ICECredentials struct {
	// Username for ICE authentication.
	Username string `json:"username"`

	// Password for ICE authentication.
	Password string `json:"password"`
}

// GenerateICEMessage creates an ICE message with host and STUN-derived candidates.
func GenerateICEMessage(messageType ICEMessageType, candidates []ICECandidate) (*ICEMessage, error) {
	message := &ICEMessage{
		Type:        messageType,
		Candidates:  candidates,
		Credentials: generateCredentials(),
	}

	if messageType == ICEMessageTypeOffer {
		message.GenerateSessionID()
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

// GenerateFoundation creates a unique foundation string for the candidate.
func GenerateFoundation(addr string) string {
	hash := sha256.Sum256([]byte(addr))
	return base64.StdEncoding.EncodeToString(hash[:8])[:8] // First 8 chars of hash
}

// generateCredentials creates ICE credentials from the encryption key.
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
