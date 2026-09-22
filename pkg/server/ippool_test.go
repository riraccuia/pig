package server

import (
	"net"
	"testing"
)

func newTestIPPool(t *testing.T, cidr string) *IPPool {
	t.Helper()
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		t.Fatalf("ParseCIDR(%q): %v", cidr, err)
	}
	return newIPPool(ipNet)
}

func TestIPPoolIPv4FirstAllocation(t *testing.T) {
	p := newTestIPPool(t, "192.168.1.0/24")
	got, err := p.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	want := net.ParseIP("192.168.1.1")
	if !got.Equal(want) {
		t.Fatalf("Allocate() = %v, want %v", got, want)
	}
}

func TestIPPoolIPv6FirstAllocation(t *testing.T) {
	p := newTestIPPool(t, "2a51:ae0:64f:4e93::/64")
	got, err := p.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	want := net.ParseIP("2a51:ae0:64f:4e93::1")
	if !got.Equal(want) {
		t.Fatalf("Allocate() = %v, want %v", got, want)
	}
}

func TestIPPoolIPv4Sequential(t *testing.T) {
	p := newTestIPPool(t, "10.0.0.0/30")
	want := []net.IP{
		net.ParseIP("10.0.0.1"),
		net.ParseIP("10.0.0.2"),
	}
	for i, w := range want {
		got, err := p.Allocate()
		if err != nil {
			t.Fatalf("Allocate #%d: %v", i, err)
		}
		if !got.Equal(w) {
			t.Fatalf("Allocate #%d = %v, want %v", i, got, w)
		}
	}
}

func TestIPPoolSetUsedSkipsReserved(t *testing.T) {
	p := newTestIPPool(t, "10.8.0.0/29")
	p.SetUsed(net.ParseIP("10.8.0.1"))
	got, err := p.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	want := net.ParseIP("10.8.0.2")
	if !got.Equal(want) {
		t.Fatalf("Allocate() = %v, want %v", got, want)
	}
}

func TestIPPoolReleaseReusesAddress(t *testing.T) {
	p := newTestIPPool(t, "10.8.0.0/30")
	first, err := p.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	if _, err := p.Allocate(); err != nil {
		t.Fatalf("Allocate second: %v", err)
	}
	if _, err := p.Allocate(); err == nil {
		t.Fatal("Allocate on full pool: want error")
	}

	p.Release(first)
	got, err := p.Allocate()
	if err != nil {
		t.Fatalf("Allocate after Release: %v", err)
	}
	if !got.Equal(first) {
		t.Fatalf("Allocate after Release = %v, want %v", got, first)
	}
}

func TestIPPoolIPv4ExhaustsWithoutNetworkOrBroadcast(t *testing.T) {
	p := newTestIPPool(t, "192.168.0.0/30")
	allocated := make(map[string]bool)
	for {
		ip, err := p.Allocate()
		if err != nil {
			break
		}
		s := ip.String()
		if allocated[s] {
			t.Fatalf("duplicate allocation: %s", s)
		}
		allocated[s] = true
	}
	if len(allocated) != 2 {
		t.Fatalf("allocated %d addresses, want 2", len(allocated))
	}
	if allocated["192.168.0.0"] {
		t.Fatal("allocated network address")
	}
	if allocated["192.168.0.3"] {
		t.Fatal("allocated broadcast address")
	}
	if !allocated["192.168.0.1"] || !allocated["192.168.0.2"] {
		t.Fatalf("allocated %v, want 192.168.0.1 and 192.168.0.2", allocated)
	}
}

func TestIPPoolIPv6SetUsedAndRelease(t *testing.T) {
	p := newTestIPPool(t, "fd00::/126")
	p.SetUsed(net.ParseIP("fd00::1"))
	got, err := p.Allocate()
	if err != nil {
		t.Fatalf("Allocate: %v", err)
	}
	want := net.ParseIP("fd00::2")
	if !got.Equal(want) {
		t.Fatalf("Allocate() = %v, want %v", got, want)
	}
	p.Release(got)
	again, err := p.Allocate()
	if err != nil {
		t.Fatalf("Allocate after Release: %v", err)
	}
	if !again.Equal(want) {
		t.Fatalf("Allocate after Release = %v, want %v", again, want)
	}
}
