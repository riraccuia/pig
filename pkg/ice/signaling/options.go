package signaling

import (
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
)

// Options provides configuration for MQTT-based hole punching
type Options struct {
	// ServerID is the identifier for the server. When set, it will be used to
	// route messages to the server instead of the server's public IP.
	ServerID string

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

	// ConnectOffset is the connect offset in milliseconds
	ConnectOffset time.Duration
}

func GetOptions(logger common.Logger, cfg *config.ICEConfig) *Options {
	connectOffset := common.DefaultConnectOffset
	if cfg.Signaling.ConnectOffset == 0 {
		connectOffset = time.Duration(cfg.Signaling.ConnectOffset) * time.Millisecond
	}
	return &Options{
		Logger:        logger,
		ServerID:      cfg.Signaling.ServerID,
		BrokerURL:     cfg.Signaling.MQTTBrokerAddress,
		ClientID:      cfg.Signaling.MQTTClientID,
		Username:      cfg.Signaling.MQTTUsername,
		Password:      cfg.Signaling.MQTTPassword,
		EncryptionKey: []byte(cfg.Signaling.EncryptionKey),
		STUNServer:    cfg.STUNAddress,
		ConnectOffset: connectOffset,
	}
}
