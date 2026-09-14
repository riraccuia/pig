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
	"fmt"
	"net"
	"slices"
	"strings"
	"time"
)

var (
	DefaultMTU           = 1400
	DefaultQueueSize     = 256
	DefaultStreamCount   = 0
	DefaultRetryInterval = 5
	DefaultWredWF        = 5.0
	DefaultWredDP        = 0.25
	DefaultWredThresh    = 0.30

	DefaultICEBrokerAddress = "ssl://broker.hivemq.com:8883"
	DefaultICEProtocol      = TransportWS
	DefaultICESTUNServer    = "stun.nextcloud.com:443"

	DefaultTunnelAddressV4Connect = "172.31.254.1/29"
	DefaultTunnelAddressV4Listen  = "172.31.255.1/24"

	DefaultConnectOffset = time.Millisecond * 500
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

	if c.STUNAddress == "" {
		c.STUNAddress = EnvSTUN.Get()
	}
	if c.STUNAddress == "" {
		c.STUNAddress = DefaultICESTUNServer
	}

	c.MQTTBroker.Initialize()

	if c.hasDefaultOrConnectTunnels() || !c.Adapter.IsZero() {
		if err := c.Adapter.Initialize(TunnelDirectionConnect); err != nil {
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

		switch c.Tunnels[i].Direction {
		case TunnelDirectionConnect:
			if c.Tunnels[i].Adapter != nil {
				return fmt.Errorf("tunnel %d: connect tunnels must use the top-level adapter", i)
			}
		case TunnelDirectionListen:
			if c.Tunnels[i].Adapter == nil {
				return fmt.Errorf("tunnel %d: listen tunnels require a dedicated adapter", i)
			}
			if err := c.Tunnels[i].Adapter.Initialize(TunnelDirectionListen); err != nil {
				return fmt.Errorf("tunnel %d: %w", i, err)
			}
		}

		adapterCfg := c.AdapterForTunnel(&c.Tunnels[i])
		if adapterCfg == nil || adapterCfg.IsZero() {
			return fmt.Errorf("tunnel %d: adapter is not configured for direction %s", i, c.Tunnels[i].Direction)
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

func (c *AdapterConfig) Initialize(direction TunnelDirection) error {
	if c.MTU == 0 {
		c.MTU = DefaultMTU
	}
	if c.QueueSize == 0 {
		c.QueueSize = DefaultQueueSize
	}
	if len(c.TunnelAddress) == 0 {
		c.TunnelAddress = []string{DefaultTunnelAddressV4Connect}
		if direction == TunnelDirectionListen {
			c.TunnelAddress = []string{DefaultTunnelAddressV4Listen}
		}
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
	if direction == TunnelDirectionConnect {
		c.TunnelAddress = append(c.TunnelAddress, DefaultTunnelAddressV4Connect)
		return nil
	}
	if direction == TunnelDirectionListen {
		c.TunnelAddress = append(c.TunnelAddress, DefaultTunnelAddressV4Listen)
	}
	return nil
}

func (c *TunnelConfig) Initialize(bindAdapter string, defaultStunServer string, defaultMqttBroker *MQTTBrokerConfig) error {
	if c.ICE == nil {
		c.ICE = &ICEConfig{Enabled: false}
	}
	if c.Auth == nil {
		c.Auth = &AuthConfig{}
	}

	if c.ReconnectInterval == 0 {
		c.ReconnectInterval = DefaultRetryInterval
	}
	if c.Wred.WeightFactor == 0 {
		c.Wred.WeightFactor = DefaultWredWF
	}
	if c.Wred.DropProbability == 0 {
		c.Wred.DropProbability = DefaultWredDP
	}
	if c.Wred.Threshold == 0 {
		c.Wred.Threshold = DefaultWredThresh
	}
	if c.StreamCount == 0 {
		c.StreamCount = DefaultStreamCount
	}
	if c.Proto == "" {
		c.Proto = DefaultICEProtocol
	}

	if c.Direction == TunnelDirectionConnect {
		if err := resolveTargetAddress(&c.Connect.Address, "connect"); err != nil {
			return err
		}
	}
	if c.Direction == TunnelDirectionListen {
		if c.Listen.Address == "" {
			c.Listen.Address = "0.0.0.0"
		}
		if err := resolveTargetAddress(&c.Listen.Address, "listen"); err != nil {
			return err
		}
	}

	if err := c.ICE.Initialize(c.Proto, defaultStunServer, defaultMqttBroker); err != nil {
		return err
	}

	if err := c.validateTransportAndTarget(bindAdapter); err != nil {
		return err
	}

	if err := c.TLSConfig.Initialize(c.Direction); err != nil {
		return err
	}

	if err := c.Auth.Initialize(c.Direction); err != nil {
		return err
	}

	return nil
}

func (c *ICEConfig) Initialize(withProto TransportType, defaultStunServer string, defaultMqttBroker *MQTTBrokerConfig) error {
	if c == nil || !c.Enabled {
		return nil
	}

	if c.STUNAddress == "" {
		c.STUNAddress = defaultStunServer
	}
	if c.Signaling == nil {
		c.Signaling = &ICESignalingOpts{}
	}
	if c.Signaling.MQTT == nil {
		c.Signaling.MQTT = defaultMqttBroker
	}

	if withProto == "." && len(c.Protos) == 0 {
		c.Protos = []string{"ws", "quic", "dtls", "tls"}
	}
	if len(c.Protos) == 0 && withProto != "" {
		c.Protos = strings.Split(string(withProto), ",")
	}
	if len(c.Protos) == 0 {
		return fmt.Errorf("no ICE protocols specified")
	}

	for _, proto := range c.Protos {
		if !TransportType(proto).IsICEProtocol() {
			return fmt.Errorf("invalid ICE protocol: %s", proto)
		}
	}

	return nil
}

func (c *AuthConfig) Initialize(direction TunnelDirection) error {
	if c == nil {
		return nil
	}

	if c.MTLS != nil {
		if err := c.MTLS.Initialize(direction); err != nil {
			return err
		}
	}

	if c.Type != "" && !c.Type.IsValid() {
		return fmt.Errorf("invalid auth type: %s", c.Type)
	}

	switch c.Type {
	case AuthTypeNone:
		return nil
	case AuthTypeJWT:
		if c.JWT == nil {
			return fmt.Errorf("JWT auth config not specified")
		}
		if direction == TunnelDirectionListen && c.JWT.PublicKeySource == "" {
			return fmt.Errorf("JWT public key source not specified")
		}
		if direction != TunnelDirectionConnect {
			break
		}
		if c.JWT.Token == "" {
			c.JWT.Token = EnvToken.Get()
		}
		if c.JWT.Token == "" {
			return fmt.Errorf("JWT token not specified")
		}
	case AuthTypeOIDC:
		if c.OIDC == nil {
			return fmt.Errorf("OIDC auth config not specified")
		}
		cfg := c.OIDC.ToConfig()
		if direction == TunnelDirectionConnect {
			if err := cfg.ValidateForClient(); err != nil {
				return err
			}
		}
		if direction == TunnelDirectionListen {
			if err := cfg.ValidateForServer(); err != nil {
				return err
			}
		}
	case AuthTypeOAuth:
		if c.OAuth == nil {
			return fmt.Errorf("OAuth auth config not specified")
		}
		cfg := c.OAuth.ToConfig()
		if direction == TunnelDirectionConnect {
			if err := cfg.ValidateForClient(); err != nil {
				return err
			}
		}
		if direction == TunnelDirectionListen {
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

func resolveTargetAddress(address *string, kind string) error {
	if *address == "" || net.ParseIP(*address) != nil {
		return nil
	}
	ips, err := net.LookupIP(*address)
	if err != nil {
		return fmt.Errorf("failed to resolve %s address: %w", kind, err)
	}
	if len(ips) == 0 {
		return fmt.Errorf("no IP addresses found for %s address: %s", kind, *address)
	}
	*address = ips[0].String()
	return nil
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
