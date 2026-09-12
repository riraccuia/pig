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

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
)

// Options provides configuration for MQTT-based hole punching.
type Options struct {
	// ServerID is the identifier for the server. When set, it will be used to
	// route messages to the server instead of the server's public IP.
	ServerID string

	// BrokerURL is the MQTT broker address (e.g., "tcp://localhost:1883").
	BrokerURL string

	// ClientID is the unique identifier for this MQTT client.
	ClientID string

	// Username is the username for the MQTT broker.
	Username string

	// Password is the password for the MQTT broker.
	Password string

	// EncryptionKey is the key for encryption and decryption.
	EncryptionKey []byte

	// Logger for debugging and error information.
	Logger common.Logger

	// STUNServer is the address of the STUN server to use for NAT traversal.
	STUNServer string

	// Protocol offers to use.
	Protocol string

	// ConnectOffset is the connect offset in milliseconds.
	ConnectOffset time.Duration
}

func GetOptions(logger common.Logger, cfg *config.ICEConfig) *Options {
	connectOffset := config.DefaultConnectOffset
	if cfg.Signaling.ConnectOffset > 0 {
		connectOffset = time.Duration(cfg.Signaling.ConnectOffset) * time.Millisecond
	}
	return &Options{
		Logger:        logger,
		ServerID:      cfg.Signaling.ServerID,
		BrokerURL:     cfg.Signaling.MQTT.Address,
		ClientID:      cfg.Signaling.MQTT.ClientID,
		Username:      cfg.Signaling.MQTT.Username,
		Password:      cfg.Signaling.MQTT.Password,
		EncryptionKey: []byte(cfg.Signaling.EncryptionKey),
		STUNServer:    cfg.STUNAddress,
		ConnectOffset: connectOffset,
	}
}
