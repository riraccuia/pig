package signaling

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"net"
	"testing"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/riraccuia/pig/pkg/ice"
)

func TestPubSubICEMessage(t *testing.T) {
	// Create client options
	opts := &Options{
		BrokerURL:  "ssl://broker.hivemq.com:8883",
		ClientID:   "pig-test-ice-client-" + time.Now().Format("20060102150405"),
		Logger:     nil, //log.NewBlockingLogger(),
		STUNServer: "stun.l.google.com:19302",
	}

	// generate random key
	iceKey := make([]byte, 32)
	_, err := rand.Read(iceKey)
	if err != nil {
		t.Fatalf("Failed to generate random key: %v", err)
	}

	opts.EncryptionKey = iceKey

	// Create client with target address
	targetAddr := "test-ice-server:1234"
	mclient, err := NewClient(opts, targetAddr)
	if err != nil {
		t.Fatalf("Failed to create client: %v", err)
	}

	// create random udp conn
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("Failed to create UDP listener: %v", err)
	}
	defer udpConn.Close()

	mserver, err := NewServer(opts, udpConn)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	mserver.topicPrefix = mclient.topicPrefix

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Subscribe and validate ICE messages
	iceMsgChan := subscribeAndValidateICE(t, opts.BrokerURL, mclient.topicPrefix+"offer/#", mserver)

	// Test publishing endpoint
	err = mclient.PublishICEOffer(ctx, udpConn)
	if err != nil {
		t.Fatalf("Failed to publish endpoint: %v", err)
	}

	// Wait for the ICE message with timeout
	select {
	case iceMsg := <-iceMsgChan:
		validateICEMessage(t, iceMsg)
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for ICE message")
	}
}

// subscribeAndValidateICE creates an MQTT subscriber that validates ICE messages
// and returns a channel that will receive the validated messages.
func subscribeAndValidateICE(t *testing.T, brokerURL string, topic string, server *Server) chan *ice.ICEMessage {
	msgChan := make(chan *ice.ICEMessage, 1)

	// Create MQTT client for subscription
	subOpts := mqtt.NewClientOptions().
		AddBroker(brokerURL).
		SetClientID("pig-test-subscriber-ice-" + time.Now().Format("20060102150405")).
		SetTLSConfig(&tls.Config{
			InsecureSkipVerify: true,
		})

	subClient := mqtt.NewClient(subOpts)
	if token := subClient.Connect(); token.Wait() && token.Error() != nil {
		t.Fatalf("Failed to connect subscriber: %v", token.Error())
	}

	// Subscribe to the topic
	if token := subClient.Subscribe(topic, 0, func(client mqtt.Client, msg mqtt.Message) {
		// Validate the ICE message
		iceMsg, err := server.validateMessage(msg.Payload())
		if err != nil {
			t.Fatalf("Failed to validate ICE message: %v", err)
			return
		}
		msgChan <- iceMsg
	}); token.Wait() && token.Error() != nil {
		t.Fatalf("Failed to subscribe: %v", token.Error())
	}

	// Cleanup will be handled by the caller
	return msgChan
}

// validateICEMessage validates ICE messages
func validateICEMessage(t *testing.T, iceMsg *ice.ICEMessage) {
	// Validate message type
	if iceMsg.Type != ice.ICEMessageTypeOffer {
		t.Errorf("Wrong message type: got %s, want %s", iceMsg.Type, ice.ICEMessageTypeOffer)
	}

	// Check for required fields
	if len(iceMsg.Candidates) == 0 {
		t.Error("No candidates in ICE message")
	} else {
		// At least one candidate should be of type srflx
		hasSrflx := false
		for _, candidate := range iceMsg.Candidates {
			if candidate.Type == ice.ICECandidateTypeSrflx {
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
