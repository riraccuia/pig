package config

import (
	"fmt"
	"net"
	"strings"
)

var (
	DefaultMTU           = 1400
	DefaultQueueSize     = 256
	DefaultStreamCount   = 0
	DefaultRetryInterval = 5
	DefaultWredWF        = 5.0
	DefaultWredDP        = 0.25
	DefaultWredThresh    = 0.30

	DefaultICEBroker     = "ssl://broker.hivemq.com:8883"
	DefaultICEProtocol   = TransportWS
	DefaultICESTUNServer = "stun.nextcloud.com:443"

	DefaultTunnelAddressClient = "172.31.254.1/29"
	DefaultTunnelAddressServer = "172.31.255.1/24"
)

func (c *Config) normalize() error {
	if c.Mode == "" {
		c.Mode = ModeClient
	}
	if !c.Mode.IsValid() {
		return fmt.Errorf("invalid pig mode: %s", c.Mode)
	}

	if c.TunnelConfig.ICE == nil {
		c.TunnelConfig.ICE = &ICEConfig{Enabled: false}
	}

	if c.TunnelConfig.MTU == 0 {
		c.TunnelConfig.MTU = DefaultMTU
	}
	if c.TunnelConfig.ReconnectInterval == 0 {
		c.TunnelConfig.ReconnectInterval = DefaultRetryInterval
	}
	if c.TunnelConfig.Wred.WeightFactor == 0 {
		c.TunnelConfig.Wred.WeightFactor = DefaultWredWF
	}
	if c.TunnelConfig.Wred.DropProbability == 0 {
		c.TunnelConfig.Wred.DropProbability = DefaultWredDP
	}
	if c.TunnelConfig.Wred.Threshold == 0 {
		c.TunnelConfig.Wred.Threshold = DefaultWredThresh
	}
	if c.TunnelConfig.QueueSize == 0 {
		c.TunnelConfig.QueueSize = DefaultQueueSize
	}
	if c.TunnelConfig.StreamCount == 0 {
		c.TunnelConfig.StreamCount = DefaultStreamCount
	}
	if c.TunnelConfig.Proto == "" {
		c.TunnelConfig.Proto = DefaultICEProtocol
	}

	if c.TunnelConfig.Target.Address != "" && net.ParseIP(c.TunnelConfig.Target.Address) == nil {
		ips, err := net.LookupIP(c.TunnelConfig.Target.Address)
		if err != nil {
			return fmt.Errorf("failed to resolve target address: %w", err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("no IP addresses found for target address: %s", c.TunnelConfig.Target.Address)
		}
		c.TunnelConfig.Target.Address = ips[0].String()
	}

	if c.TunnelConfig.TunnelAddress == "" {
		c.TunnelConfig.TunnelAddress = DefaultTunnelAddressClient
		if c.Mode == ModeServer {
			c.TunnelConfig.TunnelAddress = DefaultTunnelAddressServer
		}
	}

	if err := c.normalizeICEConfig(); err != nil {
		return err
	}
	if err := c.validateAuthConfig(); err != nil {
		return err
	}
	if err := c.validateTransportAndTarget(); err != nil {
		return err
	}

	return nil
}

func (c *Config) normalizeICEConfig() error {
	if c.TunnelConfig.ICE == nil || !c.TunnelConfig.ICE.Enabled {
		return nil
	}

	if c.TunnelConfig.ICE.STUNAddress == "" {
		c.TunnelConfig.ICE.STUNAddress = DefaultICESTUNServer
	}
	if c.TunnelConfig.ICE.Signaling == nil {
		c.TunnelConfig.ICE.Signaling = &ICESignalingOpts{}
	}
	if c.TunnelConfig.ICE.Signaling.MQTTBrokerAddress == "" {
		c.TunnelConfig.ICE.Signaling.MQTTBrokerAddress = DefaultICEBroker
	}

	if c.TunnelConfig.Proto == "." && len(c.TunnelConfig.ICE.Protos) == 0 {
		c.TunnelConfig.ICE.Protos = []string{"ws", "quic", "dtls", "tls"}
	}
	if len(c.TunnelConfig.ICE.Protos) == 0 {
		c.TunnelConfig.ICE.Protos = splitNonEmpty(string(c.TunnelConfig.Proto))
	}
	if len(c.TunnelConfig.ICE.Protos) == 0 {
		return fmt.Errorf("no ICE protocols specified")
	}

	for _, proto := range c.TunnelConfig.ICE.Protos {
		if !TransportType(proto).IsICEProtocol() {
			return fmt.Errorf("invalid ICE protocol: %s", proto)
		}
	}

	return nil
}

func (c *Config) validateAuthConfig() error {
	if c.TunnelConfig.Auth == nil {
		return nil
	}

	if c.TunnelConfig.Auth.Type != AuthTypeJWT {
		return nil
	}
	if c.TunnelConfig.Auth.JWT == nil {
		return fmt.Errorf("JWT auth config not specified")
	}
	if c.Mode == ModeServer && c.TunnelConfig.Auth.JWT.PublicKeySource == "" {
		return fmt.Errorf("JWT public key source not specified")
	}
	if c.Mode == ModeClient && c.TunnelConfig.Auth.JWT.Token == "" {
		return fmt.Errorf("JWT token not specified")
	}

	return nil
}

func (c *Config) validateTransportAndTarget() error {
	if c.needsTarget() {
		return fmt.Errorf("target address not specified")
	}

	if c.TunnelConfig.ICE != nil && c.TunnelConfig.ICE.Enabled {
		return nil
	}

	if !c.TunnelConfig.Proto.IsValid() {
		return fmt.Errorf("invalid transport: %s", c.TunnelConfig.Proto)
	}

	if c.TunnelConfig.Proto == TransportICMP || c.TunnelConfig.Proto == TransportTLSICMP {
		if c.TunnelConfig.BindAdapter == "" {
			return fmt.Errorf("bind adapter not specified, but required for %s", c.TunnelConfig.Proto)
		}
	}

	if c.TunnelConfig.Target.Port == 0 {
		if c.TunnelConfig.Proto == TransportICMP || c.TunnelConfig.Proto == TransportTLSICMP {
			return nil
		}
		return fmt.Errorf("target port not specified")
	}

	return nil
}

func (c *Config) needsTarget() bool {
	if c.TunnelConfig.Target.Address != "" {
		return false
	}
	if c.TunnelConfig.ICE == nil || !c.TunnelConfig.ICE.Enabled {
		return true
	}
	if c.TunnelConfig.ICE.Signaling == nil {
		return true
	}
	return false
}

func splitNonEmpty(value string) []string {
	parts := strings.Split(value, ",")
	protos := make([]string, 0, len(parts))

	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		protos = append(protos, trimmed)
	}

	return protos
}
