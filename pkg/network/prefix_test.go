package network

import (
	"math/rand"
	"testing"
)

func TestGenerateIpPrefix_Ipv6ULA(t *testing.T) {
	for range 100 {
		// random prefix between 8 and 128
		prefixLength := rand.Intn(128-8) + 8
		prefix, err := GenerateIPPrefix("fd00::/8", prefixLength, true)
		if err != nil {
			t.Fatalf("failed to generate IPv6 ULA prefix: %v", err)
		}
		//t.Logf("generated IPv6 ULA prefix: %s", prefix.String())
		if prefix.Bits() != prefixLength {
			t.Fatalf("generated IPv6 ULA prefix bits is not correct: %d", prefix.Bits())
		}
		if !prefix.Addr().IsPrivate() {
			t.Fatalf("generated IPv6 ULA prefix is not private: %s", prefix.String())
		}
		if !prefix.Addr().IsGlobalUnicast() {
			t.Fatalf("generated IPv6 ULA prefix is not global unicast: %s", prefix.String())
		}
	}
}

func TestGenerateIpPrefix_Ipv4Private(t *testing.T) {
	ipv4PrivatePrefixes := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	}
	for i := range 100 {
		// random prefix between 16 and 32
		prefixLength := rand.Intn(32-16) + 16
		prefix, err := GenerateIPPrefix(ipv4PrivatePrefixes[i%len(ipv4PrivatePrefixes)], prefixLength, true)
		if err != nil {
			t.Fatalf("failed to generate IPv4 private prefix: %v", err)
		}
		//t.Logf("generated IPv4 private prefix: %s", prefix.String())
		if prefix.Bits() != prefixLength {
			t.Fatalf("generated IPv4 private prefix bits is not correct: %d", prefix.Bits())
		}
		if !prefix.Addr().IsPrivate() {
			t.Fatalf("generated IPv4 private prefix is not private: %s", prefix.String())
		}
	}
}

func TestGenerateIpPrefix_Edge(t *testing.T) {
	cases := []struct {
		name                string
		baseCIDR            string
		prefixLength        int
		withFirstUsableHost bool
		wantError           bool
		expectedPrefix      string
	}{
		{
			name:                "ipv4 private prefix with first usable host",
			baseCIDR:            "192.168.0.0/16",
			prefixLength:        16,
			withFirstUsableHost: true,
			expectedPrefix:      "192.168.0.1/16",
		},
		{
			name:                "ipv4 private prefix without first usable host",
			baseCIDR:            "192.168.0.0/16",
			prefixLength:        16,
			withFirstUsableHost: false,
			expectedPrefix:      "192.168.0.0/16",
		},
		{
			name:                "ipv4 with higher prefix length than base prefix",
			baseCIDR:            "10.0.0.0/8",
			prefixLength:        24,
			withFirstUsableHost: true,
			expectedPrefix:      "10.0.0.1/24",
		},
		{
			name:                "ipv4 base and prefix length 32",
			baseCIDR:            "1.2.3.4/32",
			prefixLength:        32,
			withFirstUsableHost: true,
			expectedPrefix:      "1.2.3.4/32",
		},
		{
			name:                "target prefix smaller than base prefix",
			baseCIDR:            "172.16.0.0/12",
			prefixLength:        8,
			withFirstUsableHost: false,
			wantError:           true,
		},
		{
			name:                "target prefix 64 with ipv4 base",
			baseCIDR:            "172.16.0.0/12",
			prefixLength:        64,
			withFirstUsableHost: false,
			wantError:           true,
		},
		{
			name:                "first usable host with ipv4 base and target prefix length 32",
			baseCIDR:            "172.16.0.0/12",
			prefixLength:        32,
			withFirstUsableHost: true,
			expectedPrefix:      "172.16.0.0/32",
		},
		{
			name:                "base prefix uses non network address",
			baseCIDR:            "192.168.1.50/24",
			prefixLength:        24,
			withFirstUsableHost: true,
			expectedPrefix:      "192.168.1.1/24",
		},
		{
			name:                "ipv6 ULA prefix",
			baseCIDR:            "fd00::/8",
			prefixLength:        48,
			withFirstUsableHost: true,
			expectedPrefix:      "fd00::1/48",
		},
		{
			name:                "base prefix as empty string",
			baseCIDR:            "",
			prefixLength:        16,
			withFirstUsableHost: false,
			wantError:           true,
		},
		{
			name:                "base prefix as simple host without prefix length",
			baseCIDR:            "192.168.0.0",
			prefixLength:        16,
			withFirstUsableHost: false,
			wantError:           true,
		},
		{
			name:                "base prefix as invalid prefix",
			baseCIDR:            "not_a_prefix/12",
			prefixLength:        16,
			withFirstUsableHost: false,
			wantError:           true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			prefix, err := generateIPPrefix(tc.baseCIDR, tc.prefixLength, tc.withFirstUsableHost, false)
			if tc.wantError {
				if err == nil {
					t.Fatalf("expected error, but got no error")
				}
				return
			}
			if err != nil {
				t.Fatalf("failed to generate IP prefix: %v", err)
			}
			if prefix.String() != tc.expectedPrefix {
				t.Fatalf("generated IP prefix is not correct: %s, want: %s", prefix.String(), tc.expectedPrefix)
			}
		})
	}
}
