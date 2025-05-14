package signaling

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/stun"
)

// Client implements the client-side STUN query and MQTT publishing
type Client struct {
	opts        *Options
	topicPrefix string
}

// NewClient creates a new client
func NewClient(opts *Options, targetAddr string) (*Client, error) {
	if opts == nil {
		return nil, fmt.Errorf("Options not set")
	}

	// Set defaults
	if opts.STUNServer == "" {
		return nil, fmt.Errorf("STUN server is not set")
	}

	topicPrefixStr := getTopicPrefix(targetAddr) + "/"

	if opts.Logger != nil {
		opts.Logger.Debugf("topic prefix for signaling: %s", topicPrefixStr)
	}

	return &Client{
		opts:        opts,
		topicPrefix: topicPrefixStr,
	}, nil
}

func getTopicPrefix(targetAddr string) string {
	// the topic prefix is the sha256 hash of the target address
	topicPrefix := sha256.Sum256([]byte(targetAddr))
	// base64 encode the topic prefix
	topicPrefixStr := strings.ToLower(base64.StdEncoding.EncodeToString(topicPrefix[:]))
	// remove slashes from the topic prefix
	topicPrefixStr = strings.ReplaceAll(topicPrefixStr, "/", "")
	return topicPrefixStr
}

// PublishICEOffer performs a STUN query and publishes the result to MQTT
// It connects to the MQTT broker, publishes the message, and disconnects.
func (c *Client) PublishICEOffer(ctx context.Context, udpConn *net.UDPConn) error {
	// Perform STUN query to get our public endpoint
	mappedIP, mappedPort, err := stun.QueryServerUDP(c.opts.Logger, c.opts.STUNServer, udpConn)
	if err != nil {
		return fmt.Errorf("STUN query failed: %w", err)
	}

	// Create MQTT client options
	mqttOpts := getMQTTClientOptions(c.opts)

	// Create and connect MQTT client
	client := mqtt.NewClient(mqttOpts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to connect to MQTT broker: %w", token.Error())
	}
	defer client.Disconnect(250)

	// Get the local address
	localAddr := udpConn.LocalAddr().(*net.UDPAddr)

	// Create ICE offer message
	iceMsg := ice.GenerateICEOffer(mappedIP, mappedPort, localAddr, c.opts.EncryptionKey)

	// Marshal ICE message to JSON
	msgBytes, err := json.Marshal(iceMsg)
	if err != nil {
		return fmt.Errorf("failed to marshal ICE message: %w", err)
	}

	// Use offer topic for ICE
	topic := c.topicPrefix + "offer/"

	payload := msgBytes

	if c.opts.EncryptionKey != nil {
		// Encrypt the message
		ciphertext, err := Encrypt(msgBytes, c.opts.EncryptionKey)
		if err != nil {
			return fmt.Errorf("failed to encrypt message: %w", err)
		}
		// base64 encode the ciphertext
		ciphertextStr := base64.StdEncoding.EncodeToString(ciphertext)
		payload = []byte(ciphertextStr)
	}

	// Publish message to server topic
	if c.opts.Logger != nil {
		c.opts.Logger.Debugf("publishing ICE offer to topic: %s", topic)
	}

	if token := client.Publish(topic, 0, false, payload); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to publish ICE offer: %w", token.Error())
	}

	return nil
}
