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

package main

import (
	"testing"

	"github.com/riraccuia/pig/pkg/config"
)

func TestApplyCommandLineFlagsClientMode(t *testing.T) {
	cfg := &config.Config{}
	flags := &Flags{
		address:       "127.0.0.1:4444",
		proto:         string(config.TransportQUIC),
		srcPort:       5555,
		tunnelAddress: "10.0.0.2/32",
		certFile:      "client.pem",
		keyFile:       "client.key",
		mtlsCA:        "ca.pem",
		authType:      string(config.AuthTypeJWT),
		token:         "token-value",
		mtu:           1300,
		queueSize:     64,
	}

	applyCommandLineFlags(cfg, flags, ModeConnect, nil)

	if len(cfg.Tunnels) != 1 {
		t.Fatalf("expected one tunnel, got %d", len(cfg.Tunnels))
	}
	tc := cfg.Tunnels[0]
	if tc.Direction != config.TunnelDirectionConnect {
		t.Fatalf("expected connect direction, got %s", tc.Direction)
	}
	if tc.Connect.Address != "127.0.0.1" || tc.Connect.Port != 4444 || tc.Connect.SrcPort != 5555 {
		t.Fatalf("unexpected connect target: %#v", tc.Connect)
	}
	if cfg.Adapter.TunnelAddress[0] != "10.0.0.2/32" {
		t.Fatalf("unexpected connect adapter: %#v", cfg.Adapter)
	}
	if tc.Adapter != nil {
		t.Fatalf("unexpected tunnel adapter in client mode: %#v", tc.Adapter)
	}
	if tc.TLSConfig.CertFile != "" || tc.TLSConfig.KeyFile != "" {
		t.Fatalf("unexpected tls config: %#v", tc.TLSConfig)
	}
	if tc.Auth == nil || tc.Auth.JWT == nil || tc.Auth.JWT.Token != "token-value" {
		t.Fatalf("unexpected auth config: %#v", tc.Auth)
	}
	if tc.Auth.MTLS == nil || tc.Auth.MTLS.CertFile != "client.pem" || tc.Auth.MTLS.KeyFile != "client.key" || tc.Auth.MTLS.TrustPEM != "ca.pem" {
		t.Fatalf("unexpected mtls config: %#v", tc.Auth.MTLS)
	}
}

func TestApplyCommandLineFlagsServerMode(t *testing.T) {
	cfg := &config.Config{}
	flags := &Flags{
		address:       "0.0.0.0:7777",
		proto:         string(config.TransportTLS),
		tunnelAddress: "10.0.1.1/24",
		certFile:      "server.pem",
		keyFile:       "server.key",
		authType:      string(config.AuthTypeJWT),
		jwkSource:     "keys.json",
		mtu:           1400,
		queueSize:     128,
	}

	applyCommandLineFlags(cfg, flags, ModeListen, nil)

	if len(cfg.Tunnels) != 1 {
		t.Fatalf("expected one tunnel, got %d", len(cfg.Tunnels))
	}
	tc := cfg.Tunnels[0]
	if tc.Direction != config.TunnelDirectionListen {
		t.Fatalf("expected listen direction, got %s", tc.Direction)
	}
	if tc.Listen.Address != "0.0.0.0" || tc.Listen.Port != 7777 {
		t.Fatalf("unexpected listen target: %#v", tc.Listen)
	}
	if len(cfg.Adapter.TunnelAddress) > 0 {
		t.Fatalf("unexpected connect adapter in server mode: %#v", cfg.Adapter)
	}
	if tc.Adapter == nil || tc.Adapter.TunnelAddress[0] != "10.0.1.1/24" {
		t.Fatalf("unexpected listen adapter: %#v", tc.Adapter)
	}
	if tc.TLSConfig.CertFile != "server.pem" || tc.TLSConfig.KeyFile != "server.key" {
		t.Fatalf("unexpected tls config: %#v", tc.TLSConfig)
	}
	if tc.Auth == nil || tc.Auth.JWT == nil || tc.Auth.JWT.PublicKeySource != "keys.json" {
		t.Fatalf("unexpected auth config: %#v", tc.Auth)
	}
	if tc.Auth.MTLS != nil {
		t.Fatalf("unexpected mtls config in listen mode: %#v", tc.Auth.MTLS)
	}
}

func TestSetConfigField(t *testing.T) {
	cases := []struct {
		name     string
		field    string
		value    string
		expected string
	}{
		{
			name:     "MQTTClientID",
			field:    "",
			value:    "test-client-id",
			expected: "test-client-id",
		},
		{
			name:     "MQTTClientID",
			field:    "MQTTClientID",
			value:    "",
			expected: "MQTTClientID",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			setConfigField(&c.field, c.value)
			if c.field != c.expected {
				t.Fatalf("expected %s, got %s", c.expected, c.field)
			}
		})
	}
}
