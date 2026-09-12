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

package config

//go:generate go run ../../scripts/gen_struct_tags -type Config $GOFILE

import (
	"encoding/json/v2"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/riraccuia/pig/pkg/transport"
)

type TunnelDirection string

const (
	TunnelDirectionConnect TunnelDirection = "connect"
	TunnelDirectionListen  TunnelDirection = "listen"
)

var supportedDirections = map[TunnelDirection]bool{
	TunnelDirectionConnect: true,
	TunnelDirectionListen:  true,
}

func (d TunnelDirection) IsValid() bool {
	return supportedDirections[d]
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

func (t TransportType) Description() string {
	switch t {
	case TransportQUIC:
		return "QUIC (Quick UDP Internet Connections)"
	case TransportUDP:
		return "UDP (User Datagram Protocol)"
	case TransportTLS:
		return "TLS (Transport Layer Security)"
	case TransportWS:
		return "WebSocket"
	case TransportICMP:
		return "ICMP (ICMP tunneling), Experimental"
	case TransportTLSICMP:
		return "TLS over ICMP (ICMP tunneling), Experimental"
	case TransportDTLS:
		return "DTLS (Datagram Transport Layer Security)"
	}
	return "Unknown transport protocol"
}

var SupportedTransports = map[TransportType]bool{
	TransportQUIC:    true,
	TransportUDP:     false,
	TransportTLS:     true,
	TransportWS:      true,
	TransportICMP:    false,
	TransportTLSICMP: true,
	TransportDTLS:    true,
}

type AuthType string

const (
	AuthTypeNone AuthType = "none"
	AuthTypeJWT  AuthType = "jwt"
	AuthTypeOIDC AuthType = "oidc"
)

var supportedAuthTypes = map[AuthType]bool{
	AuthTypeNone: true,
	AuthTypeJWT:  true,
	AuthTypeOIDC: true,
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

// IsValid checks if the transport type is supported.
func (t TransportType) IsValid() bool {
	return SupportedTransports[t]
}

func (t TransportType) IsICEProtocol() bool {
	return t == TransportWS || t == TransportQUIC || t == TransportDTLS || t == TransportTLS || t == TransportTLSICMP
}

// IsValid checks if the ICMP mode is supported.
func (m ICMPMode) IsValid() bool {
	return supportedICMPModes[m]
}

type Config struct {
	// optional=true
	// desc=Logging configuration block.
	LogConfig LogConfig `toml:"log" json:"log"`
	// optional=true
	// desc=Adapter configuration block.
	Adapter AdapterConfig `toml:"adapter,omitempty" json:"adapter,omitzero"`
	// optional=true
	// desc=Route configuration block.
	RouteConfig RouteConfig `toml:"route,omitempty" json:"route,omitzero"`
	// desc=Tunnel configuration block.
	Tunnels []TunnelConfig `toml:"tunnels" json:"tunnels"`
	// default=DefaultICESTUNServer
	// optional=true
	// desc=Default STUN server address for NAT traversal in the form of host:port.
	STUNAddress string `toml:"stun_global" json:"stun_global"`
	// optional=true
	// desc=Default MQTT broker configuration for NAT traversal.
	MQTTBroker MQTTBrokerConfig `toml:"mqtt_global" json:"mqtt_global"`
	// optional=true
	// desc=Path to an executable file to call on various tunnel events.
	ScriptPath string `toml:"script_path" json:"script_path"`
}

type AdapterConfig struct {
	// desc=CIDR format.
	TunnelAddress []string `toml:"tunnel_address,omitempty" json:"tunnel_address,omitzero"`
	// default=DefaultMTU
	// desc=Maximum Transmission Unit.
	MTU int `toml:"mtu,omitzero" json:"mtu,omitzero"`
	// optional=true
	// desc=Adapter name to bind to, e.g. "eth0". Only required when 'proto' is tls-in-icmp.
	BindAdapter string `toml:"bind_adapter,omitempty" json:"bind_adapter,omitzero"`
	// default=DefaultQueueSize
	// optional=true
	// desc=Size of the network queues for the tunnel.
	QueueSize int `toml:"queue_size,omitzero" json:"queue_size,omitzero"`
}

type TunnelConfig struct {
	// desc=Friendly name for the tunnel.
	Name string `toml:"name" json:"name"`
	// desc=Tunnel direction, either "connect" or "listen".
	Direction TunnelDirection `toml:"direction" json:"direction"`
	// optional=true
	// desc=Adapter configuration specific for this tunnel. Mandatory when the direction is "listen".
	Adapter *AdapterConfig `toml:"adapter" json:"adapter"`
	// optional=true
	// desc=Connect target configuration. Use with NAT traversal disabled.
	Connect ConnectTarget `toml:"connect,omitempty" json:"connect,omitzero"`
	// optional=true
	// desc=Listen address to bind to. Use with NAT traversal disabled.
	Listen ListenTarget `toml:"listen,omitempty" json:"listen,omitzero"`
	// optional=true
	// desc=TLS configuration.
	TLSConfig TLSConfig `toml:"tls" json:"tls"`
	// default=DefaultStreamCount
	// optional=true
	// desc=Number of streams to open. Valid only with streamed protocols like QUIC. Zero means the number of CPU cores.
	StreamCount int `toml:"stream_count,omitzero" json:"stream_count,omitzero"`
	// default=DefaultICEProtocol
	// optional=true
	// desc=Transport protocol to use for the tunnel.
	Proto TransportType `toml:"proto" json:"proto"`
	// default=DefaultRetryInterval
	// optional=true
	// desc=Reconnect interval in seconds.
	ReconnectInterval int `toml:"reconnect_interval" json:"reconnect_interval"`
	// optional=true
	// desc=WRED settings.
	Wred WredConfig `toml:"wred" json:"wred"`
	// optional=true
	// desc=Authentication configuration.
	Auth *AuthConfig `toml:"auth" json:"auth"`
	// optional=true
	// desc=NAT traversal and path discovery configuration. To enable NAT traversal, set ICEConfig.Enabled=true.
	ICE *ICEConfig `toml:"ice" json:"ice"`
	// optional=true
	// desc=Routes to enforce once the tunnel is established.
	Routes []Route `toml:"routes" json:"routes"`
}

type LogConfig struct {
	// optional=true
	// desc=Path to the log file to write to. Otherwise logs to stdout.
	File string `toml:"file" json:"file"`
	// default="info"
	// optional=true
	// desc=Log level. Use one of "trace", "debug", "info", "warn", "error".
	Level string `toml:"level" json:"level"`
	// optional=true
	// desc=Size of the log file to rotate at. e.g. 100k, 1m, 1g, or actual size in bytes.
	RotateSize any `toml:"rotate_size" json:"rotate_size"`
}

type ICEConfig struct {
	// default=false
	// optional=true
	// desc=Enable ICE based network path discovery.
	Enabled bool `toml:"enabled" json:"enabled"`
	// optional=true
	// desc=Protocols to use for candidate generation.
	// Not needed when TunnelConfig.Proto is already set.
	Protos []string `toml:"protos" json:"protos"`
	// optional=true
	// desc=Optional custom STUN server to use instead of the global config.STUNAddress.
	STUNAddress string `toml:"stun_address,omitempty" json:"stun_address,omitzero"`
	// optional=true
	// desc=Signaling configuration.
	Signaling *ICESignalingOpts `toml:"signaling" json:"signaling"`
}

func (c *ICEConfig) UseProtos() (protos []transport.ICEProtocolDefinition) {
	/*if len(c.Protos) == 0 {
		return []transport.ICEProtocolDefinition{transport.ICEProtocolWS, transport.ICEProtocolQUIC}
	}*/
	for _, proto := range c.Protos {
		switch TransportType(proto) {
		case TransportWS:
			protos = append(protos, transport.ICEProtocolWS)
		case TransportQUIC:
			protos = append(protos, transport.ICEProtocolQUIC)
		case TransportDTLS:
			protos = append(protos, transport.ICEProtocolDTLS)
		case TransportTLS:
			protos = append(protos, transport.ICEProtocolTLS)
		case TransportTLSICMP:
			protos = append(protos, transport.ICEProtocolTLSInICMP)
		}
	}
	return
}

type ICESignalingOpts struct {
	// desc=Use a connection ID to identify the connection, instead of the mapped IP.
	ServerID string `toml:"server_id" json:"server_id"`
	// optional=true
	// desc=Encryption key for the signaling messages.
	EncryptionKey string `toml:"encryption_key" json:"encryption_key"`
	// default=DefaultConnectOffset
	// optional=true
	// desc=Connect offset in milliseconds.
	ConnectOffset int `toml:"connect_offset,omitzero" json:"connect_offset,omitzero"`
	// optional=true
	// desc=Optional MQTT broker configuration to use instead of the default one.
	MQTT *MQTTBrokerConfig `toml:"mqtt" json:"mqtt"`
}

type MQTTBrokerConfig struct {
	// default=DefaultICEBrokerAddress
	// desc=MQTT broker address in the form of mqtt://host:port or ssl://host:port.
	Address string `toml:"address" json:"address"`
	// optional=true
	// desc=MQTT client ID.
	ClientID string `toml:"client_id,omitempty" json:"client_id,omitzero"`
	// optional=true
	// desc=MQTT username.
	Username string `toml:"username,omitempty" json:"username,omitzero"`
	// optional=true
	// desc=MQTT password.
	Password string `toml:"password,omitempty" json:"password,omitzero"`
}

type ConnectTarget struct {
	// desc=Remote address to connect to. Fqdn or IP address.
	Address string `toml:"address,omitempty" json:"address,omitzero"`
	// desc=Target port to connect to.
	Port int `toml:"port,omitzero" json:"port,omitzero"`
	// desc=Source port to use for the connection. Leave empty for random selection.
	SrcPort int `toml:"src_port,omitzero" json:"src_port,omitzero"`
}

type ListenTarget struct {
	// desc=Local address to listen on.
	Address string `toml:"address" json:"address"`
	// desc=Local port to listen on.
	Port int `toml:"port,omitzero" json:"port,omitzero"`
}

type WredConfig struct {
	// default=DefaultWredWF
	// optional=true
	// desc=Weight factor. Lower values give more weight to recent packets.
	WeightFactor float64 `toml:"weight_factor" json:"weight_factor"`
	// default=DefaultWredDP
	// optional=true
	// desc=Probability for packets to be dropped on busy queues. Accepts decimals between 0 and 1.
	DropProbability float64 `toml:"drop_probability" json:"drop_probability"`
	// default=DefaultWredThresh
	// optional=true
	// desc=Threshold for WRED as a fraction of the queue length. Accepts decimals between 0 and 1.
	Threshold float64 `toml:"threshold" json:"threshold"`
}

type TLSConfig struct {
	// optional=true
	// desc=Insecure is the flag to skip TLS certificate verification.
	Insecure bool `toml:"insecure" json:"insecure"`
	// optional=true
	// desc=CertFile is the local certificate presented by listen tunnels.
	CertFile string `toml:"cert_file" json:"cert_file"`
	// optional=true
	// desc=KeyFile is the private key for CertFile.
	KeyFile string `toml:"key_file" json:"key_file"`
}

type AuthConfig struct {
	// default=AuthTypeNone
	// optional=true
	// desc=One of "none", "jwt", "oidc".
	Type AuthType `toml:"type" json:"type"`
	// optional=true
	// desc=JWT authentication configuration.
	JWT *JWTAuth `toml:"jwt" json:"jwt"`
	// optional=true
	// desc=OIDC authentication configuration.
	OIDC *OIDCAuth `toml:"oidc" json:"oidc"`
	// optional=true
	// desc=MTLS authentication configuration.
	MTLS *MTLSConfig `toml:"mtls" json:"mtls"`
}

type MTLSConfig struct {
	// optional=true
	// desc=TrustPEM is the path to the trust bundle for MTLS, if not provided, the system CA will be used.
	// In client mode, this is used to validate the server certificate.
	// In server mode, this is used to validate client certificates.
	TrustPEM string `toml:"trust_pem" json:"trust_pem"`
	// optional=true
	// desc=CertFile is the client certificate presented by connect tunnels.
	CertFile string `toml:"cert_file" json:"cert_file"`
	// optional=true
	// desc=KeyFile is the private key for CertFile.
	KeyFile string `toml:"key_file" json:"key_file"`
}

type JWTAuth struct {
	// desc=PublicKeySource is the path to the public key file used to verify peer JWT tokens.
	PublicKeySource string `toml:"public_key_source" json:"public_key_source"`
	// desc=Token is the JWT token presented to the peer during authentication.
	Token string `toml:"token" json:"token"`
}

// OIDCAuth holds OpenID Connect settings matching pkg/auth/oidc.Config (TOML-friendly types).
type OIDCAuth struct {
	// desc=Issuer URL of the provider.
	IssuerURL string `toml:"issuer_url" json:"issuer_url"`
	// desc=Client ID of the application.
	ClientID string `toml:"client_id" json:"client_id"`
	// desc=Client secret of the application.
	ClientSecret string `toml:"client_secret" json:"client_secret"`
	// desc=Scopes for the authorization request (optional; oidc package defaults apply when empty).
	Scopes []string `toml:"scopes" json:"scopes"`
	// desc=RedirectURL is the full OAuth redirect URI registered at the IdP (optional; loopback ephemeral port if empty).
	RedirectURL string `toml:"redirect_url" json:"redirect_url"`
	// desc=RedirectPath is used only when RedirectURL is empty (default in oidc is /oauth2/callback).
	RedirectPath string `toml:"redirect_path" json:"redirect_path"`
	// desc=Skip opening the browser for the authorization code flow.
	SkipOpenBrowser bool `toml:"skip_open_browser" json:"skip_open_browser"`
	// desc=CallbackTimeoutSeconds bounds browser redirect wait (zero = oidc default).
	CallbackTimeoutSeconds int    `toml:"callback_timeout_seconds" json:"callback_timeout_seconds"`
	ExpectedAudience       string `toml:"expected_audience" json:"expected_audience"`
	// desc=ClockSkewSeconds is leeway for id_token exp/iat (zero = oidc default).
	ClockSkewSeconds int `toml:"clock_skew_seconds" json:"clock_skew_seconds"`
	// desc=Disable Proof Key for Code Exchange (PKCE).
	DisablePKCE bool `toml:"disable_pkce" json:"disable_pkce"`
	// desc=ClaimMatchers see pkg/auth/oidc.Config.ClaimMatchers.
	ClaimMatchers map[string]any `toml:"claim_matchers" json:"claim_matchers"`
}

type RouteType string

const (
	RouteTypeTunnel RouteType = "tunnel"
	RouteTypeBypass RouteType = "bypass"
	RouteTypeStatic RouteType = "static"
)

type Route struct {
	// desc=Destination CIDR to route. E.g. "192.168.1.0/24".
	Destination string `toml:"destination" json:"destination"`
	// desc=Type of route. One of "tunnel", "bypass", "static".
	Type RouteType `toml:"type" json:"type"`
	// optional=true
	// desc=For "static" routes, the gateway IP address to use for the route.
	Gateway string `toml:"gateway,omitempty" json:"gateway,omitzero"`
	// optional=true
	// desc=For "static" routes, the interface name to use for the route.
	Interface string `toml:"interface,omitempty" json:"interface,omitzero"`
}

func routeTypePriority(t RouteType) int {
	switch t {
	case RouteTypeBypass:
		return 0
	case RouteTypeStatic:
		return 1
	case RouteTypeTunnel:
		return 2
	default:
		return 3 // unknown types go last
	}
}

type RouteConfig struct {
	// default=false
	// optional=true
	// desc=Enable route configuration.
	Enabled bool `toml:"enabled,omitempty" json:"enabled,omitzero"`
	// optional=true
	// desc=Routes are the routes that will be used for the routing.
	Routes []Route `toml:"routes" json:"routes"`
}

func LoadConfigFromFile(path string) (*Config, error) {
	// determine the config type based on the file extension
	// if the extension is .toml, decode as toml
	// if the extension is .json, decode as json
	extension := strings.ToLower(filepath.Ext(path))
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}
	switch extension {
	case ".toml":
		return LoadConfigFromBytes(data, "toml")
	case ".json":
		return LoadConfigFromBytes(data, "json")
	default:
		return nil, fmt.Errorf("unsupported config format: %s", extension)
	}
}

func LoadConfigFromBytes(data []byte, decodeAs string) (*Config, error) {
	config := &Config{}
	switch decodeAs {
	case "toml":
		if _, err := toml.Decode(string(data), config); err != nil {
			return nil, err
		}
	case "json":
		if err := json.Unmarshal(data, config); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("unsupported config format: %s", decodeAs)
	}
	err := config.Initialize()
	if err != nil {
		return nil, err
	}
	return config, nil
}

func (c AdapterConfig) IsZero() bool {
	return len(c.TunnelAddress) == 0 && c.MTU == 0 && c.BindAdapter == "" && c.QueueSize == 0
}

func (c *Config) HasConnectTunnels() bool {
	for i := range c.Tunnels {
		if c.Tunnels[i].Direction == TunnelDirectionConnect {
			return true
		}
	}
	return false
}

func (c *Config) HasListenTunnels() bool {
	for i := range c.Tunnels {
		if c.Tunnels[i].Direction == TunnelDirectionListen {
			return true
		}
	}
	return false
}

func (c *Config) AdapterForTunnel(tunnel *TunnelConfig) *AdapterConfig {
	if tunnel == nil {
		return nil
	}
	if tunnel.Direction == TunnelDirectionListen {
		return tunnel.Adapter
	}
	if tunnel.Direction == TunnelDirectionConnect {
		return &c.Adapter
	}
	return nil
}

func (c *TunnelConfig) EndpointAddress() string {
	if c.Direction == TunnelDirectionListen {
		return c.Listen.Address
	}
	return c.Connect.Address
}

func (c *TunnelConfig) EndpointPort() int {
	if c.Direction == TunnelDirectionListen {
		return c.Listen.Port
	}
	return c.Connect.Port
}
