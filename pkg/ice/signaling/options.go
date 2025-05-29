package signaling

import (
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
)

// Options provides configuration for MQTT-based hole punching
type Options struct {
	// BrokerURL is the MQTT broker address (e.g., "tcp://localhost:1883")
	BrokerURL string

	// ClientID is the unique identifier for this MQTT client
	ClientID string

	// Username is the username for the MQTT broker
	Username string

	// Password is the password for the MQTT broker
	Password string

	// EncryptionKey is the key for encryption and decryption
	EncryptionKey []byte

	// Logger for debugging and error information
	Logger common.Logger

	// STUNServer is the address of the STUN server to use for NAT traversal
	STUNServer string

	// Protocol offers to use
	Protocol string
}

func GetOptions(logger common.Logger, cfg *config.ICEConfig) *Options {
	return &Options{
		Logger:        logger,
		BrokerURL:     cfg.Signaling.MQTTBrokerAddress,
		ClientID:      cfg.Signaling.MQTTClientID,
		Username:      cfg.Signaling.MQTTUsername,
		Password:      cfg.Signaling.MQTTPassword,
		EncryptionKey: []byte(cfg.Signaling.EncryptionKey),
		STUNServer:    cfg.STUNAddress,
	}
}
