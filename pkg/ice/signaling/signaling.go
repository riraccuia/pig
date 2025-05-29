package signaling

import (
	"context"
	"fmt"
	"net"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/stun"
)

// Signaler handles ICE signaling operations
type Signaler struct {
	ctx         context.Context
	opts        *Options
	mqttClient  mqtt.Client
	stunUdpConn *net.UDPConn
}

// NewSignaler creates a new signaler instance
func NewSignaler(ctx context.Context, opts *Options) (*Signaler, error) {
	if opts == nil {
		return nil, fmt.Errorf("Options not set")
	}

	if opts.STUNServer == "" {
		return nil, fmt.Errorf("STUN server is not set")
	}

	// Create and connect MQTT client
	client, err := connectMQTTClient(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to MQTT broker %s: %w", opts.BrokerURL, err)
	}

	return &Signaler{
		ctx:        ctx,
		opts:       opts,
		mqttClient: client,
	}, nil
}

func (s *Signaler) SetSTUNUDPConn(conn *net.UDPConn) {
	s.stunUdpConn = conn
}

// GatherICECandidates performs a STUN query, publishes an offer, and waits for an answer
func GatherICECandidates(ctx context.Context, opts *Options, localAddr, targetAddr net.Addr) (ic []message.ICECandidate, err error) {
	signaler, err := NewSignaler(ctx, opts)
	defer signaler.Disconnect()
	if err != nil {
		return nil, err
	}
	ic, err = signaler.GatherICECandidates(localAddr, targetAddr)
	return
}

// GatherICECandidates performs a STUN query, publishes an offer, and waits for an answer
func (s *Signaler) GatherICECandidates(localAddr net.Addr, targetAddr net.Addr) ([]message.ICECandidate, error) {
	// Get mapped endpoint
	mappedIP, mappedPort, err := s.PerformSTUNQuery(localAddr)
	if err != nil {
		return nil, fmt.Errorf("STUN query failed: %w", err)
	}

	host, _, err := net.SplitHostPort(targetAddr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to split host and port: %w", err)
	}

	topicBase := s.getTopicPrefix(host) + "/"
	iceMsg, err := s.publishICEOffer(topicBase, mappedIP, mappedPort, localAddr)
	if err != nil {
		return nil, err
	}
	// Wait for answer
	return s.waitForAnswer(topicBase, iceMsg.SessionID)
}

// PerformSTUNQuery performs a STUN query to get the public endpoint
func (s *Signaler) PerformSTUNQuery(localAddr net.Addr) (mappedIP net.IP, mappedPort int, err error) {
	// Perform STUN query to get our public endpoint
	switch localAddr.Network() {
	case "udp":
		var connOrSrcPort any = localAddr.(*net.UDPAddr).Port
		if s.stunUdpConn != nil {
			connOrSrcPort = s.stunUdpConn
		}
		mappedIP, mappedPort, err = stun.QueryServerUDP(s.opts.Logger, s.opts.STUNServer, connOrSrcPort)
	case "tcp":
		mappedIP, mappedPort, err = stun.QueryServerTCP(s.opts.Logger, s.opts.STUNServer, localAddr.(*net.TCPAddr).Port)
	default:
		return nil, 0, fmt.Errorf("unsupported network type: %s", localAddr.Network())
	}

	return mappedIP, mappedPort, err
}

func (s *Signaler) GetOptions() *Options {
	return s.opts
}

func (s *Signaler) Disconnect() {
	if s.mqttClient == nil {
		return
	}
	s.mqttClient.Disconnect(250)
}
