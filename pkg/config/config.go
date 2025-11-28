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

func (t TransportType) IsICEProtocol() bool {
	return t == TransportWS || t == TransportQUIC || t == TransportDTLS || t == TransportTLS || t == TransportTLSICMP
}

// IsValid checks if the ICMP mode is supported
func (m ICMPMode) IsValid() bool {
	return supportedICMPModes[m]
}

type Config struct {
	Mode              Mode          `toml:"mode" json:"mode"`                     // "client" or "server"
	LogConfig         LogConfig     `toml:"log" json:"log"`                       // Log configuration
	TunnelAddress     string        `toml:"tunnel_address" json:"tunnel_address"` // CIDR format
	MTU               int           `toml:"mtu" json:"mtu"`
	CertFile          string        `toml:"cert_file" json:"cert_file"`
	KeyFile           string        `toml:"key_file" json:"key_file"`
	StreamCount       int           `toml:"stream_count" json:"stream_count"`
	Insecure          bool          `toml:"insecure" json:"insecure"` // Skip TLS certificate verification if true
	Proto             TransportType `toml:"proto" json:"proto"`
	Target            Target        `toml:"target" json:"target"`
	ReconnectInterval int           `toml:"reconnect_interval" json:"reconnect_interval"` // in seconds
	BindAdapter       string        `toml:"bind_adapter" json:"bind_adapter"`             // The adapter to bind to
	Wred              WredConfig    `toml:"wred" json:"wred"`
	StartScript       string        `toml:"start_script" json:"start_script"` // Script to execute when a tunnel connection is established
	StopScript        string        `toml:"stop_script" json:"stop_script"`   // Script to execute when a tunnel connection is disconnected
	Auth              *AuthConfig   `toml:"auth" json:"auth"`
	QueueSize         int           `toml:"queue_size" json:"queue_size"` // Size of packet queues (default: 256)
	ICE               *ICEConfig    `toml:"ice" json:"ice"`
}

type LogConfig struct {
	File       string `toml:"file" json:"file"`               // Path to log file
	Level      string `toml:"level" json:"level"`             // Log level
	RotateSize any    `toml:"rotate_size" json:"rotate_size"` // e.g. 100k, 1m, 1g, or actual size in bytes
}

type ICEConfig struct {
	Enabled     bool              `toml:"enabled" json:"enabled"`           // Enable ICE based hole punching
	Protos      []string          `toml:"protos" json:"protos"`             // Protocols to use for ICE
	STUNAddress string            `toml:"stun_address" json:"stun_address"` // STUN server address
	Signaling   *ICESignalingOpts `toml:"signaling" json:"signaling"`       // Signaling options
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
		case "tls":
			protos = append(protos, transport.ICEProtocolTLS)
		case "tls-in-icmp":
			protos = append(protos, transport.ICEProtocolTLSInICMP)
		}
	}
	return
}

type ICESignalingOpts struct {
	ServerID          string `toml:"server_id" json:"server_id"`                     // Use a connection ID to identify the connection, instead of the mapped IP
	EncryptionKey     string `toml:"encryption_key" json:"encryption_key"`           // Encryption key for the ICE signaling
	ConnectOffset     int    `toml:"connect_offset" json:"connect_offset"`           // Connect offset in milliseconds
	MQTTBrokerAddress string `toml:"mqtt_broker_address" json:"mqtt_broker_address"` // MQTT broker address in the form of mqtt://host:port or ssl://host:port
	MQTTClientID      string `toml:"mqtt_client_id" json:"mqtt_client_id"`           // MQTT client ID
	MQTTUsername      string `toml:"mqtt_username" json:"mqtt_username"`             // MQTT username
	MQTTPassword      string `toml:"mqtt_password" json:"mqtt_password"`             // MQTT password
}

type Target struct {
	Address string `toml:"address" json:"address"`
	Port    int    `toml:"port" json:"port"`
	SrcPort int    `toml:"src_port" json:"src_port"`
}

type WredConfig struct {
	WeightFactor    float64 `toml:"weight_factor" json:"weight_factor"`
	DropProbability float64 `toml:"drop_probability" json:"drop_probability"`
	Threshold       float64 `toml:"threshold" json:"threshold"`
}

type AuthConfig struct {
	Type AuthType    `toml:"type" json:"type"`
	JWT  *JWTAuth    `toml:"jwt" json:"jwt"`
	MTLS *MTLSConfig `toml:"mtls" json:"mtls"`
}

type MTLSConfig struct {
	// TrustPEM is the path to the trust bundle for MTLS, if not provided, the system CA will be used
	// in client mode, this is used to validate the server certificate
	// in server mode, this is used to validate client certificates
	TrustPEM string `toml:"trust_pem" json:"trust_pem"`
}

type JWTAuth struct {
	// PublicKeySource is the path to the public key file for JWT verification
	PublicKeySource string `toml:"public_key_source" json:"public_key_source"`
	// Token is the JWT token to use for authentication (client only)
	Token string `toml:"token" json:"token"`
}

func LoadConfig(path string) (*Config, error) {
	var config Config
	if _, err := toml.DecodeFile(path, &config); err != nil {
		return nil, err
	}
	return &config, nil
}
