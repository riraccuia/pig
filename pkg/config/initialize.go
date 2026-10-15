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

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/riraccuia/pig/pkg/network"
)

var (
	DefaultMTU           = 1420
	DefaultQueueSize     = 256
	DefaultStreamCount   = 0
	DefaultIdleTimeout   = 0
	DefaultRetryInterval = 5
	DefaultWredWF        = 9.0
	DefaultWredDP        = 0.1
	DefaultWredThresh    = 0.5
	DefaultWredMinThresh = math.Round(DefaultWredThresh*0.5*100) / 100 // half of the max threshold

	DefaultICEBrokerAddress = "ssl://broker.hivemq.com:8883"
	DefaultICEProtocol      = TransportWS
	DefaultICESTUNServer    = "stun.nextcloud.com:443"

	DefaultConnectBasePrefixV4   = "100.64.0.0/11"
	DefaultListenBasePrefixV4    = "100.96.0.0/11"
	DefaultConnectPrefixLengthV4 = 30
	DefaultListenPrefixLengthV4  = 16

	DefaultConnectOffset = time.Millisecond * 500

	DefaultWGKeepaliveConnect = 25
	DefaultWGAllowedIPs       = []string{"0.0.0.0/0", "::/0"}
)

func (b *MQTTBrokerConfig) Initialize() error {
	if b.Address == "" {
		b.Address = EnvMQTTBroker.Get()
	}
	if b.Address == "" {
		b.Address = DefaultICEBrokerAddress
	}
	if b.ClientID == "" {
		b.ClientID = EnvMQTTClientID.Get()
	}
	if b.Username == "" {
		b.Username = EnvMQTTUsername.Get()
	}
	if b.Password == "" {
		b.Password = EnvMQTTPassword.Get()
	}
	return nil
}

func (c *Config) Initialize() error {
	if err := c.LogConfig.Initialize(); err != nil {
		return err
	}

	if len(c.STUNAddress) == 0 {
		for _, s := range strings.Split(EnvSTUN.Get(), ",") {
			if s = strings.TrimSpace(s); s != "" {
				c.STUNAddress = append(c.STUNAddress, s)
			}
		}
	}
	if len(c.STUNAddress) == 0 {
		c.STUNAddress = []string{DefaultICESTUNServer}
	}

	c.MQTTBroker.Initialize()

	if c.hasDefaultOrConnectTunnels() || !c.Adapter.IsZero() {
		if err := c.Adapter.InitializeDefaultAdapter(); err != nil {
			return err
		}
	}

	for i := range c.Tunnels {
		if c.Tunnels[i].Direction == "" {
			c.Tunnels[i].Direction = TunnelDirectionConnect
		}
		if !c.Tunnels[i].Direction.IsValid() {
			return fmt.Errorf("tunnel %d: invalid direction: %s", i, c.Tunnels[i].Direction)
		}
		if c.Tunnels[i].Name == "" {
			c.Tunnels[i].Name = fmt.Sprintf("tunnel-%d", i)
		}

		var adapterToInitialize *AdapterConfig
		switch c.Tunnels[i].Direction {
		case TunnelDirectionConnect:
			if c.Tunnels[i].Adapter != nil {
				adapterToInitialize = c.Tunnels[i].Adapter
			}
		case TunnelDirectionListen:
			if c.Tunnels[i].Adapter == nil {
				// listen tunnels require a dedicated adapter
				c.Tunnels[i].Adapter = &AdapterConfig{}
			}
			adapterToInitialize = c.Tunnels[i].Adapter
		}

		if adapterToInitialize != nil {
			if err := adapterToInitialize.InitializeTunnelAdapter(c.Tunnels[i].Direction); err != nil {
				return fmt.Errorf("tunnel %d: %w", i, err)
			}
		}

		adapterCfg := c.AdapterForTunnel(&c.Tunnels[i])
		if adapterCfg == nil || adapterCfg.IsZero() {
			return fmt.Errorf("tunnel %d: adapter is not configured for tunnel %s", i, c.Tunnels[i].Name)
		}
		if err := c.Tunnels[i].Initialize(adapterCfg.BindAdapter, c.STUNAddress, &c.MQTTBroker); err != nil {
			return fmt.Errorf("tunnel %d: %w", i, err)
		}
	}

	if err := c.RouteConfig.Initialize(); err != nil {
		return err
	}
	return nil
}

func (c *Config) hasDefaultOrConnectTunnels() bool {
	for i := range c.Tunnels {
		if c.Tunnels[i].Direction == "" || c.Tunnels[i].Direction == TunnelDirectionConnect {
			return true
		}
	}
	return false
}

func (c *LogConfig) Initialize() error {
	if c.Level == "" {
		c.Level = "info"
	}
	return nil
}

func (c *RouteConfig) Initialize() error {
	if !c.Enabled || len(c.Routes) < 2 {
		return nil
	}

	slices.SortStableFunc(c.Routes, func(a, b Route) int {
		return routeTypePriority(a.Type) - routeTypePriority(b.Type)
	})

	return nil
}

func (c *AdapterConfig) InitializeTunnelAdapter(direction TunnelDirection) error {
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.QueueSize == 0 {
		c.QueueSize = DefaultQueueSize
	}
	if len(c.TunnelAddress) != 0 {
		return nil
	}
	var (
		generatedNet netip.Prefix
		err          error
	)
	switch direction {
	case TunnelDirectionConnect:
		generatedNet, err = network.GenerateIPPrefix(DefaultConnectBasePrefixV4, DefaultConnectPrefixLengthV4, true)
	case TunnelDirectionListen:
		generatedNet, err = network.GenerateIPPrefix(DefaultListenBasePrefixV4, DefaultListenPrefixLengthV4, true)
	}
	if err != nil {
		return fmt.Errorf("failed to generate tunnel adapter address: %w", err)
	}
	c.TunnelAddress = []string{generatedNet.String()}
	return nil
}

func (c *AdapterConfig) InitializeDefaultAdapter() error {
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.QueueSize == 0 {
		c.QueueSize = DefaultQueueSize
	}
	if len(c.TunnelAddress) == 0 {
		generatedNet, err := network.GenerateIPPrefix(DefaultConnectBasePrefixV4, DefaultConnectPrefixLengthV4, true)
		if err != nil {
			return fmt.Errorf("failed to generate tunnel adapter address: %w", err)
		}
		c.TunnelAddress = []string{generatedNet.String()}
		return nil
	}
	hasV4Address := false
	for _, address := range c.TunnelAddress {
		if _, ipNet, err := net.ParseCIDR(address); err == nil && ipNet.IP.To4() != nil {
			hasV4Address = true
			break
		}
	}
	if hasV4Address {
		return nil
	}
	generatedNet, err := network.GenerateIPPrefix(DefaultConnectBasePrefixV4, DefaultConnectPrefixLengthV4, true)
	if err != nil {
		return fmt.Errorf("failed to generate tunnel adapter address: %w", err)
	}
	c.TunnelAddress = append(c.TunnelAddress, generatedNet.String())
	return nil
}

func (c *TunnelConfig) Initialize(bindAdapter string, globalStunServers []string, defaultMqttBroker *MQTTBrokerConfig) error {
	if c.ICE == nil {
		c.ICE = &ICEConfig{Enabled: false}
	}
	if c.Adapter != nil && c.Adapter.BindAdapter != "" {
		bindAdapter = c.Adapter.BindAdapter
	}
	if c.IdleTimeout == 0 {
		c.IdleTimeout = DefaultIdleTimeout
	}
	if c.ReconnectInterval == 0 {
		c.ReconnectInterval = DefaultRetryInterval
	}
	if c.Wred.WeightFactor == 0 {
		c.Wred.WeightFactor = DefaultWredWF
	}
	if c.Wred.MaxDropProbability == 0 {
		c.Wred.MaxDropProbability = DefaultWredDP
	}
	if c.Wred.MaxThreshold == 0 {
		c.Wred.MaxThreshold = DefaultWredThresh
	}
	if c.Wred.MinThreshold == 0 {
		c.Wred.MinThreshold = DefaultWredMinThresh
	}
	if c.StreamCount == 0 {
		c.StreamCount = DefaultStreamCount
	}
	if c.Proto == "" {
		c.Proto = DefaultICEProtocol
	}

	/*if c.Direction == TunnelDirectionConnect {
		if err := resolveTargetAddress(&c.Connect.Address, "connect"); err != nil {
			return err
		}
	}
	if c.Direction == TunnelDirectionListen {
		if c.Listen.Address == "" {
			c.Listen.Address = ""
		}
		if err := resolveTargetAddress(&c.Listen.Address, "listen"); err != nil {
			return err
		}
	}*/

	if err := c.validateTransportAndTarget(bindAdapter); err != nil {
		return err
	}

	if err := c.TLSConfig.Initialize(c.Direction); err != nil {
		return err
	}

	if err := c.InitializeICE(bindAdapter, globalStunServers, defaultMqttBroker); err != nil {
		return err
	}

	if err := c.InitializeTrust(); err != nil {
		return err
	}

	if err := c.InitializeAuth(); err != nil {
		return err
	}

	return nil
}

func (c *WireGuardConfig) Initialize(direction TunnelDirection) error {
	if c.PrivateKey == "" {
		c.PrivateKey = EnvWGPrivateKey.Get()
	}

	if err := validateWGKey(c.PrivateKey, "private_key"); err != nil {
		return err
	}

	pubKeyFromEnv := EnvWGPeerPublicKey.Get()

	if len(c.Peers) == 0 {
		if pubKeyFromEnv == "" {
			return errors.New("wireguard peer public key not specified")
		}
		c.Peers = []WireGuardPeer{
			{
				PublicKey:    pubKeyFromEnv,
				PresharedKey: EnvWGPSK.Get(),
				AllowedIPs:   DefaultWGAllowedIPs,
				Keepalive:    DefaultWGKeepaliveConnect,
			},
		}
	}

	for i := range c.Peers {
		if err := validateWGKey(c.Peers[i].PublicKey, "peer_public_key"); err != nil {
			return err
		}
		if c.Peers[i].PresharedKey != "" {
			if err := validateWGKey(c.Peers[i].PresharedKey, "preshared_key"); err != nil {
				return err
			}
		}
		if c.Peers[i].Keepalive == 0 && direction == TunnelDirectionConnect {
			c.Peers[i].Keepalive = DefaultWGKeepaliveConnect
		}
		if len(c.Peers[i].AllowedIPs) == 0 {
			c.Peers[i].AllowedIPs = append([]string(nil), DefaultWGAllowedIPs...)
		}
		for _, cidr := range c.Peers[i].AllowedIPs {
			if _, _, err := net.ParseCIDR(cidr); err != nil {
				return fmt.Errorf("invalid wireguard allowed_ips %q: %w", cidr, err)
			}
		}
	}

	return nil
}

func validateWGKey(key, field string) error {
	if key == "" {
		return fmt.Errorf("wireguard %s not specified", field)
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return fmt.Errorf("wireguard %s is not valid base64: %w", field, err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("wireguard %s must decode to 32 bytes", field)
	}
	return nil
}

// dotExpandICEProtos resolves all the ICE protocols that are supported by the tunnel config.
// It is used with the idiomatic proto = "." syntax meaning "all pig supported ICE-capable protocols".
func (c *TunnelConfig) dotExpandICEProtos() []string {
	c.ICE.Protos = []string{string(TransportWS), string(TransportQUIC), string(TransportTLS), string(TransportDTLS)}
	hasWGConfig := c.Trust != nil && c.Trust.WireGuard != nil
	hasWGEnv := EnvWGPrivateKey.Get() != "" && EnvWGPeerPublicKey.Get() != ""
	if !hasWGConfig && !hasWGEnv {
		return c.ICE.Protos
	}
	// only use wireguard if there's a valid trust configuration for it
	c.ICE.Protos = append(c.ICE.Protos, string(TransportWG))
	return c.ICE.Protos
}

func (c *TunnelConfig) InitializeICE(bindAdapter string, globalStunServers []string, defaultMqttBroker *MQTTBrokerConfig) error {
	if c.ICE == nil || !c.ICE.Enabled {
		return nil
	}

	if len(c.ICE.STUNAddress) == 0 {
		c.ICE.STUNAddress = globalStunServers
	}
	if c.ICE.Signaling == nil {
		c.ICE.Signaling = &ICESignalingOpts{}
	}
	if c.ICE.Signaling.MQTT == nil {
		c.ICE.Signaling.MQTT = defaultMqttBroker
	}
	if c.Proto == "." && len(c.ICE.Protos) == 0 {
		c.ICE.Protos = c.dotExpandICEProtos()
	}
	if len(c.ICE.Protos) == 0 && c.Proto != "" {
		c.ICE.Protos = strings.Split(string(c.Proto), ",")
	}
	if len(c.ICE.Protos) == 0 {
		return fmt.Errorf("no ICE protocols specified")
	}

	var hasWG bool
	for _, proto := range c.ICE.Protos {
		p := TransportType(proto)
		switch {
		case !p.IsICEProtocol():
			return fmt.Errorf("invalid ICE protocol: %s", proto)
		case p == TransportWG:
			hasWG = true
		case p == TransportTLSICMP && bindAdapter == "":
			return fmt.Errorf("bind adapter not specified, but required for %s", proto)
		}
	}

	if !hasWG {
		return nil
	}
	// make sure that the trust config can be initialized
	if c.Trust == nil {
		c.Trust = &TrustConfig{}
	}
	if c.Trust.WireGuard == nil {
		c.Trust.WireGuard = &WireGuardConfig{}
	}
	return nil
}

// InitializeTrust initializes the trust config, it must be called after the ICE config is initialized
func (c *TunnelConfig) InitializeTrust() error {
	if c == nil {
		return nil
	}

	if c.Trust != nil {
		if c.Trust.MTLS != nil {
			if err := c.Trust.MTLS.Initialize(c.Direction); err != nil {
				return err
			}
		}

		if c.Trust.WireGuard != nil {
			if err := c.Trust.WireGuard.Initialize(c.Direction); err != nil {
				return err
			}
		}
	}

	if c.Proto != TransportWG {
		return nil
	}

	if c.ICE != nil && c.ICE.Enabled {
		return nil
	}

	if c.Trust != nil && c.Trust.WireGuard != nil {
		return nil
	}

	if c.Trust == nil {
		c.Trust = &TrustConfig{}
	}
	if c.Trust.WireGuard == nil {
		c.Trust.WireGuard = &WireGuardConfig{}
	}
	if err := c.Trust.WireGuard.Initialize(c.Direction); err != nil {
		return err
	}

	return nil
}

func (c *TunnelConfig) InitializeAuth() error {
	if c == nil || c.Auth == nil {
		return nil
	}

	if c.Auth.Type != "" && !c.Auth.Type.IsValid() {
		return fmt.Errorf("invalid auth type: %s", c.Auth.Type)
	}

	if c.Auth.Type == "" {
		c.Auth.Type = AuthTypeNone
	}

	switch c.Auth.Type {
	case AuthTypeNone:
		return nil
	case AuthTypeJWT:
		if c.Auth.JWT == nil {
			return fmt.Errorf("JWT auth config not specified")
		}
		if c.Direction == TunnelDirectionListen && c.Auth.JWT.PublicKeySource == "" {
			return fmt.Errorf("JWT public key source not specified")
		}
		if c.Direction != TunnelDirectionConnect {
			break
		}
		if c.Auth.JWT.Token == "" {
			c.Auth.JWT.Token = EnvToken.Get()
		}
		if c.Auth.JWT.Token == "" {
			return fmt.Errorf("JWT token not specified")
		}
	case AuthTypeOIDC:
		if c.Auth.OIDC == nil {
			return fmt.Errorf("OIDC auth config not specified")
		}
		cfg := c.Auth.OIDC.ToConfig()
		if c.Direction == TunnelDirectionConnect {
			if err := cfg.ValidateForClient(); err != nil {
				return err
			}
		}
		if c.Direction == TunnelDirectionListen {
			if err := cfg.ValidateForServer(); err != nil {
				return err
			}
		}
	case AuthTypeOAuth:
		if c.Auth.OAuth == nil {
			return fmt.Errorf("OAuth auth config not specified")
		}
		cfg := c.Auth.OAuth.ToConfig()
		if c.Direction == TunnelDirectionConnect {
			if err := cfg.ValidateForClient(); err != nil {
				return err
			}
		}
		if c.Direction == TunnelDirectionListen {
			if err := cfg.ValidateForServer(); err != nil {
				return err
			}
		}
	}
	return nil
}

func (c *MTLSConfig) Initialize(direction TunnelDirection) error {
	if c == nil {
		return nil
	}

	if direction == TunnelDirectionListen {
		return nil
	}

	if (c.CertFile == "") != (c.KeyFile == "") {
		return fmt.Errorf("both MTLS cert_file and key_file must be specified together")
	}

	return nil
}

func (c *TunnelConfig) validateTransportAndTarget(bindAdapter string) error {
	if c.Direction == TunnelDirectionConnect && c.needsConnectTarget() {
		return fmt.Errorf("connect address not specified")
	}

	if c.ICE != nil && c.ICE.Enabled {
		return nil
	}

	if !c.Proto.IsValid() {
		return fmt.Errorf("invalid transport: %s", c.Proto)
	}

	if c.Proto == TransportICMP || c.Proto == TransportTLSICMP {
		if bindAdapter == "" {
			return fmt.Errorf("bind adapter not specified, but required for %s", c.Proto)
		}
	}

	if c.Direction == TunnelDirectionListen {
		return nil
	}

	if c.Connect.Port == 0 {
		if c.Proto == TransportICMP || c.Proto == TransportTLSICMP {
			return nil
		}
		return fmt.Errorf("connect port not specified")
	}

	return nil
}

func (c *TunnelConfig) needsConnectTarget() bool {
	if c.Connect.Address != "" {
		return false
	}
	if c.ICE == nil || !c.ICE.Enabled {
		return true
	}
	if c.ICE.Signaling == nil {
		return true
	}
	if c.ICE.Signaling.ServerID != "" {
		// If the server ID is set, we don't need to target the server,
		// because the server will be discovered by the server ID
		return false
	}
	return true
}

func (c *TLSConfig) Initialize(direction TunnelDirection) error {
	if (c.CertFile == "") != (c.KeyFile == "") {
		return fmt.Errorf("both TLS cert_file and key_file must be specified together")
	}
	if direction == TunnelDirectionListen && c.CertFile == "" {
		return nil
	}
	return nil
}
