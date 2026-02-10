package config

import (
	"bytes"
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
