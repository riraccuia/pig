package signaling

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/riraccuia/pig/pkg/ice"
	"github.com/riraccuia/pig/pkg/ice/punch"
	"github.com/riraccuia/pig/pkg/stun"
)

// Server implements the server-side hole punching mechanism
type Server struct {
	opts        *Options
	client      mqtt.Client
	udpConn     *net.UDPConn
	publicIP    net.IP
	publicPort  int
	topicPrefix string
	done        chan struct{}
}

// NewServer creates a new server-side hole puncher
func NewServer(opts *Options, udpConn *net.UDPConn) (*Server, error) {
	if opts == nil {
		return nil, fmt.Errorf("Options not set")
	}

	// Set defaults
	if opts.STUNServer == "" {
		return nil, fmt.Errorf("STUN server is not set")
	}

	// Perform STUN query to get our public IP
	mappedIP, mappedPort, err := stun.QueryServerUDP(opts.Logger, opts.STUNServer, udpConn)
	if err != nil {
		opts.Logger.Errorf("STUN query failed: %v", err)
		// Continue with nil IP, we'll attempt to recover later
	}

	topicPrefix := getTopicPrefix(fmt.Sprintf("%s:%d", mappedIP.String(), udpConn.LocalAddr().(*net.UDPAddr).Port)) + "/"
	if opts.Logger != nil {
		opts.Logger.Debugf("topic prefix for signaling: %s", topicPrefix)
	}

	return &Server{
		opts:        opts,
		udpConn:     udpConn,
		publicIP:    mappedIP,
		publicPort:  mappedPort,
		topicPrefix: topicPrefix,
		done:        make(chan struct{}),
	}, nil
}

// Start initializes the server and begins listening for client requests
func (s *Server) Start(ctx context.Context) error {
	// Create MQTT client options
	mqttOpts := getMQTTClientOptions(s.opts)

	mqttOpts.SetConnectionLostHandler(func(client mqtt.Client, err error) {
		if s.opts.Logger != nil {
			s.opts.Logger.Errorf("MQTT connection lost: %v", err)
		}
	})

	// Create and connect MQTT client
	s.client = mqtt.NewClient(mqttOpts)
	if token := s.client.Connect(); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to connect to MQTT broker %s: %w", mqttOpts.Servers[0], token.Error())
	}

	// Subscribe to client topic pattern for ICE offer messages
	topic := s.topicPrefix + "offer/#"
	if token := s.client.Subscribe(topic, 0, s.handleClientRequest); token.Wait() && token.Error() != nil {
		return fmt.Errorf("failed to subscribe to client topic: %w", token.Error())
	}

	go func() {
		select {
		// Wait for context cancellation
		case <-ctx.Done():
			s.opts.Logger.Info("context cancelled, closing signaling listener")
			s.Stop()
		case <-s.done:
			s.opts.Logger.Info("signaling listener closed")
		}
	}()

	return nil
}

// Stop gracefully shuts down the server
func (s *Server) Stop() error {
	if s.client != nil && s.client.IsConnected() {
		s.client.Disconnect(250)
	}
	close(s.done)
	return nil
}

// handleClientRequest processes incoming client ICE offer messages
func (s *Server) handleClientRequest(client mqtt.Client, msg mqtt.Message) {
	// Parse the topic to extract base topic
	topicParts := strings.Split(msg.Topic(), "/")
	if len(topicParts) < 2 {
		if s.opts.Logger != nil {
			s.opts.Logger.Errorf("Invalid topic format: %s", msg.Topic())
		}
		return
	}

	// Get the base topic (used for answer)
	// baseTopic := topicParts[0]

	// Validate the ICE message
	iceMsg, err := s.validateMessage(msg.Payload())
	if err != nil {
		if s.opts.Logger != nil {
			s.opts.Logger.Errorf("Invalid ICE message: %v", err)
		}
		return
	}

	// Get the preferred candidate address for hole punching
	address, port, err := ice.GetPreferredCandidate(iceMsg)
	if err != nil {
		if s.opts.Logger != nil {
			s.opts.Logger.Errorf("Failed to get preferred candidate: %v", err)
		}
		return
	}

	targetAddr := fmt.Sprintf("%s:%d", address, port)

	// If we have valid public endpoints, send an ICE answer
	// if s.publicIP != nil && s.publicPort != 0 {
	// s.sendICEAnswer(baseTopic, iceMsg.Credentials)
	// }

	// Perform hole punch to client
	_, err = punch.PunchUDP(context.Background(), s.opts.Logger, s.udpConn, targetAddr)
	if err != nil {
		s.opts.Logger.Errorf("Failed to punch UDP: %v", err)
		return
	}

	s.opts.Logger.Infof("Hole punched to %s", targetAddr)
}

// validateMessage decrypts and validates an ICE message
func (s *Server) validateMessage(msg []byte) (*ice.ICEMessage, error) {
	var (
		payload []byte
		err     error
	)
	if s.opts.EncryptionKey != nil {
		// Decrypt the message
		ciphertext, err := base64.StdEncoding.DecodeString(string(msg))
		if err != nil {
			return nil, fmt.Errorf("failed to decode message: %w", err)
		}

		decrypted, err := Decrypt(ciphertext, s.opts.EncryptionKey)
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt message: %w", err)
		}
		payload = decrypted
	}
	// Parse the ICE message
	var iceMsg ice.ICEMessage
	if err = json.Unmarshal(payload, &iceMsg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal ICE message: %w", err)
	}

	return &iceMsg, nil
}

// sendICEAnswer sends an ICE answer message back to the client
func (s *Server) sendICEAnswer(topicBase string, credentials ice.ICECredentials) {
	// Get our local address
	localAddr := s.udpConn.LocalAddr().(*net.UDPAddr)

	// Create an ICE answer message
	answer := ice.GenerateICEAnswer(s.publicIP, s.publicPort, localAddr, s.opts.EncryptionKey)

	// Use the credentials from the request
	answer.Credentials = credentials

	// Marshal the message
	msgBytes, err := json.Marshal(answer)
	if err != nil {
		s.opts.Logger.Errorf("Failed to marshal ICE answer: %v", err)
		return
	}

	// Encrypt the message
	ciphertext, err := Encrypt(msgBytes, s.opts.EncryptionKey)
	if err != nil {
		s.opts.Logger.Errorf("Failed to encrypt ICE answer: %v", err)
		return
	}

	// base64 encode the ciphertext
	ciphertextStr := base64.StdEncoding.EncodeToString(ciphertext)

	// Publish to the answer topic
	topic := topicBase + "/answer/"
	s.opts.Logger.Infof("Publishing ICE answer to topic: %s", topic)

	if token := s.client.Publish(topic, 0, false, ciphertextStr); token.Wait() && token.Error() != nil {
		s.opts.Logger.Errorf("Failed to publish ICE answer: %v", token.Error())
	}
}
