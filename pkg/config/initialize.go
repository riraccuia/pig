package config

import (
	"fmt"
	"net"
	"slices"
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

func (c *Config) Initialize() error {
	if c.Mode == "" {
		c.Mode = ModeClient
	}
	if !c.Mode.IsValid() {
		return fmt.Errorf("invalid pig mode: %s", c.Mode)
	}

	if err := c.LogConfig.Initialize(); err != nil {
		return err
	}

	if err := c.TunnelConfig.Initialize(c.Mode); err != nil {
		return err
	}

	if err := c.RouteConfig.Initialize(); err != nil {
		return err
	}

	return nil
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

func (c *TunnelConfig) Initialize(mode Mode) error {
	if c.ICE == nil {
		c.ICE = &ICEConfig{Enabled: false}
	}

	if c.Auth == nil {
		c.Auth = &AuthConfig{}
	}

	if c.MTU == 0 {
		c.MTU = DefaultMTU
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
	if c.QueueSize == 0 {
		c.QueueSize = DefaultQueueSize
	}
	if c.StreamCount == 0 {
		c.StreamCount = DefaultStreamCount
	}
	if c.Proto == "" {
		c.Proto = DefaultICEProtocol
	}

	if c.Target.Address != "" && net.ParseIP(c.Target.Address) == nil {
		ips, err := net.LookupIP(c.Target.Address)
		if err != nil {
			return fmt.Errorf("failed to resolve target address: %w", err)
		}
		if len(ips) == 0 {
			return fmt.Errorf("no IP addresses found for target address: %s", c.Target.Address)
		}
		c.Target.Address = ips[0].String()
	}

	if c.TunnelAddress == "" {
		c.TunnelAddress = DefaultTunnelAddressClient
		if mode == ModeServer {
			c.TunnelAddress = DefaultTunnelAddressServer
		}
	}

	if err := c.ICE.Initialize(c.Proto); err != nil {
		return err
	}

	if err := c.validateTransportAndTarget(); err != nil {
		return err
	}

	if err := c.Auth.Initialize(mode); err != nil {
		return err
	}

	return nil
}

func (c *ICEConfig) Initialize(withProto TransportType) error {
	if c == nil || !c.Enabled {
		return nil
	}

	if c.STUNAddress == "" {
		c.STUNAddress = DefaultICESTUNServer
	}
	if c.Signaling == nil {
		c.Signaling = &ICESignalingOpts{}
	}
	if c.Signaling.MQTTBrokerAddress == "" {
		c.Signaling.MQTTBrokerAddress = DefaultICEBroker
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

func (c *AuthConfig) Initialize(mode Mode) error {
	if c == nil {
		return nil
	}

	if c.Type != AuthTypeJWT {
		return nil
	}
	if c.JWT == nil {
		return fmt.Errorf("JWT auth config not specified")
	}
	if mode == ModeServer && c.JWT.PublicKeySource == "" {
		return fmt.Errorf("JWT public key source not specified")
	}
	if mode == ModeClient && c.JWT.Token == "" {
		return fmt.Errorf("JWT token not specified")
	}

	return nil
}

func (c *TunnelConfig) validateTransportAndTarget() error {
	if c.needsTarget() {
		return fmt.Errorf("target address not specified")
	}

	if c.ICE != nil && c.ICE.Enabled {
		return nil
	}

	if !c.Proto.IsValid() {
		return fmt.Errorf("invalid transport: %s", c.Proto)
	}

	if c.Proto == TransportICMP || c.Proto == TransportTLSICMP {
		if c.BindAdapter == "" {
			return fmt.Errorf("bind adapter not specified, but required for %s", c.Proto)
		}
	}

	if c.Target.Port == 0 {
		if c.Proto == TransportICMP || c.Proto == TransportTLSICMP {
			return nil
		}
		return fmt.Errorf("target port not specified")
	}

	return nil
}

func (c *TunnelConfig) needsTarget() bool {
	if c.Target.Address != "" {
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
