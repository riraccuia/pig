package config

import (
	"github.com/BurntSushi/toml"
)

type TransportType string

const (
	TransportQUIC    TransportType = "quic"
	TransportUDP     TransportType = "udp"
	TransportTLS     TransportType = "tls"
	TransportWS      TransportType = "ws"
	TransportICMP    TransportType = "icmp"
	TransportTLSICMP TransportType = "tls-in-icmp"
)

var supportedTransports = map[TransportType]bool{
	TransportQUIC:    true,
	TransportUDP:     true,
	TransportTLS:     true,
	TransportWS:      true,
	TransportICMP:    true,
	TransportTLSICMP: true,
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
	Mode              string        `toml:"mode"`           // "client" or "server"
	TunnelAddress     string        `toml:"tunnel_address"` // CIDR format
	MTU               int           `toml:"mtu"`
	CertFile          string        `toml:"cert_file"`
	KeyFile           string        `toml:"key_file"`
	StreamCount       int           `toml:"stream_count"`
	Insecure          bool          `toml:"insecure"` // Skip TLS certificate verification if true
	Transport         TransportType `toml:"transport"`
	Target            Target        `toml:"target"`
	ReconnectInterval int           `toml:"reconnect_interval"` // in seconds
	BindAdapter       string        `toml:"bind_adapter"`       // The adapter to bind to
	Wred              WredConfig    `toml:"wred"`
	LogLevel          string        `toml:"log_level"`
	ICMPMode          ICMPMode      `toml:"icmp_mode"`
	StartScript       string        `toml:"start_script"` // Script to execute when a tunnel connection is established
	StopScript        string        `toml:"stop_script"`  // Script to execute when a tunnel connection is disconnected
	Auth              *AuthConfig   `toml:"auth"`
}

type Target struct {
	Address string `toml:"address"`
	Port    int    `toml:"port"`
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
