package config

import (
	"github.com/BurntSushi/toml"
	"github.com/riraccuia/pig/pkg/transport"
)

type Mode string

const (
	ModeClient Mode = "client"
	ModeServer Mode = "server"
)

var supportedModes = map[Mode]bool{
	ModeClient: true,
	ModeServer: true,
}

func (m Mode) IsValid() bool {
	return supportedModes[m]
}

type TransportType string

const (
	TransportQUIC    TransportType = "quic"
	TransportUDP     TransportType = "udp"
	TransportTLS     TransportType = "tls"
	TransportWS      TransportType = "ws"
	TransportICMP    TransportType = "icmp"
	TransportTLSICMP TransportType = "tls-in-icmp"
	TransportDTLS    TransportType = "dtls"
)

var supportedTransports = map[TransportType]bool{
	TransportQUIC:    true,
	TransportUDP:     true,
	TransportTLS:     true,
	TransportWS:      true,
	TransportICMP:    true,
	TransportTLSICMP: true,
	TransportDTLS:    true,
}

type AuthType string

const (
	AuthTypeJWT AuthType = "jwt"
)

var supportedAuthTypes = map[AuthType]bool{
	AuthTypeJWT: true,
}

func (t AuthType) IsValid() bool {
	return supportedAuthTypes[t]
}

type ICMPMode string

const (
	ICMPModeNormal     ICMPMode = "normal"
	ICMPModeAggressive ICMPMode = "aggressive"
)

var supportedICMPModes = map[ICMPMode]bool{
	ICMPModeNormal:     true,
	ICMPModeAggressive: true,
}

// IsValid checks if the transport type is supported
func (t TransportType) IsValid() bool {
	return supportedTransports[t]
}

// IsValid checks if the ICMP mode is supported
func (m ICMPMode) IsValid() bool {
	return supportedICMPModes[m]
}

type Config struct {
	Mode              Mode          `toml:"mode"`           // "client" or "server"
	LogConfig         LogConfig     `toml:"log"`            // Log configuration
	TunnelAddress     string        `toml:"tunnel_address"` // CIDR format
	MTU               int           `toml:"mtu"`
	CertFile          string        `toml:"cert_file"`
	KeyFile           string        `toml:"key_file"`
	StreamCount       int           `toml:"stream_count"`
	Insecure          bool          `toml:"insecure"` // Skip TLS certificate verification if true
	Proto             TransportType `toml:"proto"`
	Target            Target        `toml:"target"`
	ReconnectInterval int           `toml:"reconnect_interval"` // in seconds
	BindAdapter       string        `toml:"bind_adapter"`       // The adapter to bind to
	Wred              WredConfig    `toml:"wred"`
	StartScript       string        `toml:"start_script"` // Script to execute when a tunnel connection is established
	StopScript        string        `toml:"stop_script"`  // Script to execute when a tunnel connection is disconnected
	Auth              *AuthConfig   `toml:"auth"`
	QueueSize         int           `toml:"queue_size"` // Size of packet queues (default: 256)
	ICE               *ICEConfig    `toml:"ice"`
}

type LogConfig struct {
	File       string `toml:"file"`        // Path to log file
	Level      string `toml:"level"`       // Log level
	RotateSize any    `toml:"rotate_size"` // e.g. 100k, 1m, 1g, or actual size in bytes
}

type ICEConfig struct {
	Enabled     bool              `toml:"enabled"`      // Enable ICE based hole punching
	Protos      []string          `toml:"protos"`       // Protocols to use for ICE
	STUNAddress string            `toml:"stun_address"` // STUN server address
	Signaling   *ICESignalingOpts `toml:"signaling"`    // Signaling options
}

func (c *ICEConfig) UseProtos() (protos []transport.ICEProtocolDefinition) {
	/*if len(c.Protos) == 0 {
		return []transport.ICEProtocolDefinition{transport.ICEProtocolWS, transport.ICEProtocolQUIC}
	}*/
	for _, proto := range c.Protos {
		switch proto {
		case "ws":
			protos = append(protos, transport.ICEProtocolWS)
		case "quic":
			protos = append(protos, transport.ICEProtocolQUIC)
		case "dtls":
			protos = append(protos, transport.ICEProtocolDTLS)
		}
	}
	return
}

type ICESignalingOpts struct {
	EncryptionKey     string `toml:"encryption_key"`      // Encryption key for the ICE signaling
	MQTTBrokerAddress string `toml:"mqtt_broker_address"` // MQTT broker address in the form of mqtt://host:port or ssl://host:port
	MQTTClientID      string `toml:"mqtt_client_id"`      // MQTT client ID
	MQTTUsername      string `toml:"mqtt_username"`       // MQTT username
	MQTTPassword      string `toml:"mqtt_password"`       // MQTT password
}

type Target struct {
	Address string `toml:"address"`
	Port    int    `toml:"port"`
	SrcPort int    `toml:"src_port"`
}

type WredConfig struct {
	WeightFactor    float64 `toml:"weight_factor"`
	DropProbability float64 `toml:"drop_probability"`
	Threshold       float64 `toml:"threshold"`
}

type AuthConfig struct {
	Type AuthType    `toml:"type"`
	JWT  *JWTAuth    `toml:"jwt"`
	MTLS *MTLSConfig `toml:"mtls"`
}

type MTLSConfig struct {
	// TrustPEM is the path to the trust bundle for MTLS, if not provided, the system CA will be used
	// in client mode, this is used to validate the server certificate
	// in server mode, this is used to validate client certificates
	TrustPEM string `toml:"trust_pem"`
}

type JWTAuth struct {
	// PublicKeySource is the path to the public key file for JWT verification
	PublicKeySource string `toml:"public_key_source"`
	// Token is the JWT token to use for authentication (client only)
	Token string `toml:"token"`
}

func LoadConfig(path string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return nil, err
	}
	return &config, nil
}
