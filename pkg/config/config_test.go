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
	"bytes"
	"math/rand"
	"reflect"
	"testing"

	"github.com/BurntSushi/toml"
)

func TestTOMLConfigUnmarshal(t *testing.T) {
	// Create a test configuration with ICE and signaling
	cfg := &Config{
		Adapter: AdapterConfig{
			TunnelAddress: []string{"10.0.0.1/24"},
			MTU:           1500,
		},
		Tunnels: []TunnelConfig{
			{
				Direction: TunnelDirectionConnect,
				Proto:     TransportQUIC,
				Connect: ConnectTarget{
					Address: "example.com",
					Port:    443,
				},
				ICE: &ICEConfig{
					Enabled:     true,
					STUNAddress: "stun.server.com:19302",
					Signaling: &ICESignalingOpts{
						EncryptionKey: "test-encryption-key",
						MQTT: &MQTTBrokerConfig{
							Address:  "ssl://test.broker.org:8883",
							ClientID: "test-client-id",
							Username: "test-user",
							Password: "test-password",
						},
					},
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

func TestConfigInitializeUsesDirectionSpecificAdapterDefaults(t *testing.T) {
	cfg := &Config{
		Tunnels: []TunnelConfig{
			{
				Direction: TunnelDirectionConnect,
				Connect: ConnectTarget{
					Address: "127.0.0.1",
					Port:    1,
				},
			},
			{
				Direction: TunnelDirectionListen,
				Adapter:   &AdapterConfig{},
				Listen: ListenTarget{
					Address: "127.0.0.1",
				},
			},
		},
	}

	if err := cfg.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}

	if cfg.Adapter.TunnelAddress[0] != DefaultTunnelAddressV4Connect {
		t.Fatalf("unexpected connect adapter default: %s", cfg.Adapter.TunnelAddress)
	}
	if cfg.Tunnels[1].Adapter == nil || cfg.Tunnels[1].Adapter.TunnelAddress[0] != DefaultTunnelAddressV4Listen {
		t.Fatalf("unexpected listen adapter default: %#v", cfg.Tunnels[1].Adapter)
	}
}

func TestConfigInitializeDefaultsTunnelDirectionToConnect(t *testing.T) {
	cfg := &Config{
		Tunnels: []TunnelConfig{{
			Connect: ConnectTarget{
				Address: "127.0.0.1",
				Port:    1,
			},
		}},
	}

	if err := cfg.Initialize(); err != nil {
		t.Fatalf("Initialize failed: %v", err)
	}
	if got := cfg.Tunnels[0].Direction; got != TunnelDirectionConnect {
		t.Fatalf("unexpected default tunnel direction: %s", got)
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

	for i := 1; i < len(cfg.RouteConfig.Routes); i++ {
		prev := routeTypePriority(cfg.RouteConfig.Routes[i-1].Type)
		curr := routeTypePriority(cfg.RouteConfig.Routes[i].Type)
		if prev > curr {
			t.Fatalf("routes are not ordered by type priority at index %d: %s before %s", i, cfg.RouteConfig.Routes[i-1].Type, cfg.RouteConfig.Routes[i].Type)
		}
	}
}
