package config

import (
	"bytes"
	"encoding/base64"
	"slices"
	"testing"
)

func TestTunnelConfigInitializeWireGuard(t *testing.T) {
	priv := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32))
	pub := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{2}, 32))

	tests := []struct {
		name        string
		env         map[string]string
		tc          TunnelConfig
		wantErr     bool
		wantWG      bool // trust.wireguard non-nil and keys usable
		wantWGinICE bool // "wg" present in ice.protos after init (ICE only)
	}{
		// --- without ICE (simple mode) ---
		{
			name: "no ICE: wg loads trust from env",
			env:  map[string]string{"PIG_WG_PRIVATE_KEY": priv, "PIG_WG_PEER_PUBLIC_KEY": pub},
			tc: TunnelConfig{
				Direction: TunnelDirectionConnect,
				Proto:     TransportWG,
				Connect:   ConnectTarget{Address: "127.0.0.1", Port: 51820},
				ICE:       &ICEConfig{Enabled: false},
			},
			wantWG: true,
		},
		{
			name: "no ICE: wg without keys fails",
			tc: TunnelConfig{
				Direction: TunnelDirectionConnect,
				Proto:     TransportWG,
				Connect:   ConnectTarget{Address: "127.0.0.1", Port: 51820},
				ICE:       &ICEConfig{Enabled: false},
			},
			wantErr: true,
		},
		{
			name: "no ICE: wg with keys already in trust",
			tc: TunnelConfig{
				Direction: TunnelDirectionConnect,
				Proto:     TransportWG,
				Connect:   ConnectTarget{Address: "127.0.0.1", Port: 51820},
				ICE:       &ICEConfig{Enabled: false},
				Trust: &TrustConfig{WireGuard: &WireGuardConfig{
					PrivateKey: priv,
					Peers:      []WireGuardPeer{{PublicKey: pub}},
				}},
			},
			wantWG: true,
		},
		{
			name: "no ICE: non-wg proto leaves wireguard unset",
			tc: TunnelConfig{
				Direction: TunnelDirectionConnect,
				Proto:     TransportQUIC,
				Connect:   ConnectTarget{Address: "127.0.0.1", Port: 443},
				ICE:       &ICEConfig{Enabled: false},
			},
			wantWG: false,
		},

		// --- with ICE ---
		{
			name: "ICE: proto wg loads trust from env",
			env:  map[string]string{"PIG_WG_PRIVATE_KEY": priv, "PIG_WG_PEER_PUBLIC_KEY": pub},
			tc: TunnelConfig{
				Direction: TunnelDirectionConnect,
				Proto:     TransportWG,
				ICE: &ICEConfig{
					Enabled:   true,
					Signaling: &ICESignalingOpts{ServerID: "peer"},
				},
			},
			wantWG:      true,
			wantWGinICE: true,
		},
		{
			name: "ICE: proto wg without keys fails",
			tc: TunnelConfig{
				Direction: TunnelDirectionConnect,
				Proto:     TransportWG,
				ICE: &ICEConfig{
					Enabled:   true,
					Signaling: &ICESignalingOpts{ServerID: "peer"},
				},
			},
			wantErr: true,
		},
		{
			name: "ICE: explicit proto wg without keys fails",
			tc: TunnelConfig{
				Direction: TunnelDirectionConnect,
				ICE: &ICEConfig{
					Enabled:   true,
					Protos:    []string{string(TransportWG)},
					Signaling: &ICESignalingOpts{ServerID: "peer"},
				},
			},
			wantErr: true,
		},
		{
			name: "ICE: dot without trust.wireguard and no env keys omits wg",
			tc: TunnelConfig{
				Direction: TunnelDirectionConnect,
				Proto:     ".",
				ICE: &ICEConfig{
					Enabled:   true,
					Signaling: &ICESignalingOpts{ServerID: "peer"},
				},
			},
			wantWG:      false,
			wantWGinICE: false,
		},
		{
			name: "ICE: dot with empty trust.wireguard but keys in env includes wg",
			env:  map[string]string{"PIG_WG_PRIVATE_KEY": priv, "PIG_WG_PEER_PUBLIC_KEY": pub},
			tc: TunnelConfig{
				Direction: TunnelDirectionConnect,
				Proto:     ".",
				ICE: &ICEConfig{
					Enabled:   true,
					Signaling: &ICESignalingOpts{ServerID: "peer"},
				},
				//Trust: &TrustConfig{WireGuard: &WireGuardConfig{}},
			},
			wantWG:      true,
			wantWGinICE: true,
		},
		{
			name: "ICE: env alone with dot enables wg",
			env:  map[string]string{"PIG_WG_PRIVATE_KEY": priv, "PIG_WG_PEER_PUBLIC_KEY": pub},
			tc: TunnelConfig{
				Direction: TunnelDirectionConnect,
				Proto:     ".",
				ICE: &ICEConfig{
					Enabled:   true,
					Signaling: &ICESignalingOpts{ServerID: "peer"},
				},
			},
			wantWG:      true,
			wantWGinICE: true,
		},
		{
			name: "ICE listen: proto wg from env",
			env:  map[string]string{"PIG_WG_PRIVATE_KEY": priv, "PIG_WG_PEER_PUBLIC_KEY": pub},
			tc: TunnelConfig{
				Direction: TunnelDirectionListen,
				Proto:     TransportWG,
				Listen:    ListenTarget{Address: "0.0.0.0", Port: 51820},
				ICE: &ICEConfig{
					Enabled:   true,
					Signaling: &ICESignalingOpts{ServerID: "peer"},
				},
			},
			wantWG:      true,
			wantWGinICE: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("PIG_WG_PRIVATE_KEY", "")
			t.Setenv("PIG_WG_PEER_PUBLIC_KEY", "")
			t.Setenv("PIG_WG_PSK", "")
			for k, v := range tt.env {
				t.Setenv(k, v)
			}

			tc := tt.tc
			err := tc.Initialize("", []string{"stun.example:3478"}, &MQTTBrokerConfig{})
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			gotWG := tc.Trust != nil && tc.Trust.WireGuard != nil
			if gotWG != tt.wantWG {
				t.Fatalf("wantWG=%v got %v", tt.wantWG, gotWG)
			}
			if tt.wantWG {
				wg := tc.Trust.WireGuard
				if wg.PrivateKey != priv {
					t.Fatalf("private_key: got %q want %q", wg.PrivateKey, priv)
				}
				if len(wg.Peers) == 0 || wg.Peers[0].PublicKey != pub {
					t.Fatalf("peers[0].public_key: got %#v want %q", wg.Peers, pub)
				}
			}

			if tc.ICE == nil || !tc.ICE.Enabled {
				return
			}
			has := slices.Contains(tc.ICE.Protos, string(TransportWG))
			if has != tt.wantWGinICE {
				t.Fatalf("wantWGinICE=%v got protos %v", tt.wantWGinICE, tc.ICE.Protos)
			}
		})
	}
}
