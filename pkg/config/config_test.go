package config

import (
	"bytes"
	"math/rand"
	"reflect"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestTOMLConfigUnmarshal(t *testing.T) {
	// Create a test configuration with ICE and signaling
	cfg := &Config{
		Mode: ModeClient,
		TunnelConfig: TunnelConfig{
			TunnelAddress: "10.0.0.1/24",
			MTU:           1500,
			Proto:         TransportQUIC,
			Target: Target{
				Address: "example.com",
				Port:    443,
			},
			ICE: &ICEConfig{
				Enabled:     true,
				STUNAddress: "stun.server.com:19302",
				Signaling: &ICESignalingOpts{
					EncryptionKey:     "test-encryption-key",
					MQTTBrokerAddress: "ssl://test.broker.org:8883",
					MQTTClientID:      "test-client-id",
					MQTTUsername:      "test-user",
					MQTTPassword:      "test-password",
				},
			},
		},
		LogConfig: LogConfig{
			File:       "pig.log",
			Level:      "debug",
			RotateSize: "5m",
		},
	}

	// Encode the configuration to TOML
	var (
		err error
		buf bytes.Buffer
	)

	encoder := toml.NewEncoder(&buf)
	err = encoder.Encode(cfg)
	if err != nil {
		t.Fatalf("Failed to encode TOML: %v", err)
	}

	// Output the TOML configuration
	// t.Logf("Generated TOML configuration:\n%s", buf.String())

	cfg2 := &Config{}
	err = toml.Unmarshal(buf.Bytes(), cfg2)
	if err != nil {
		t.Fatalf("Failed to unmarshal TOML: %v", err)
	}
	if !reflect.DeepEqual(cfg, cfg2) {
		t.Fatalf("Config mismatch: %+#v != %+#v", cfg, cfg2)
	}
}

func TestRouteConfigNormalization(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	routeTypes := []RouteType{RouteTypeTunnel, RouteTypeBypass, RouteTypeStatic}
	routes := make([]Route, 0, 9)

	for i := 0; i < 9; i++ {
		routes = append(routes, Route{
			Destination: "10.0.0.0/24",
			Type:        routeTypes[rng.Intn(len(routeTypes))],
		})
	}

	cfg := &Config{
		RouteConfig: RouteConfig{
			Enabled: true,
			Routes:  routes,
		},
	}
	err := cfg.RouteConfig.Initialize()
	if err != nil {
		t.Fatalf("Failed to normalize route config: %v", err)
	}

	/*for _, route := range cfg.RouteConfig.Routes {
		t.Logf("RouteType: %s", route.Type)
	}*/

	for i := 1; i < len(cfg.RouteConfig.Routes); i++ {
		prev := routeTypePriority(cfg.RouteConfig.Routes[i-1].Type)
		curr := routeTypePriority(cfg.RouteConfig.Routes[i].Type)
		if prev > curr {
			t.Fatalf("routes are not ordered by type priority at index %d: %s before %s", i, cfg.RouteConfig.Routes[i-1].Type, cfg.RouteConfig.Routes[i].Type)
		}
	}
}
