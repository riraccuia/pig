package adapter

import (
	"net"
	"reflect"
	"slices"
	"testing"
)

func TestRankIPAddr(t *testing.T) {
	unsortedAddrs := []net.IP{
		// Link-local address
		net.ParseIP("fe80::1ff:fe23:4567"),
		// Unique local address
		net.ParseIP("fda0:9b02:3ffa::2"),
		// Public address
		net.ParseIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334"),
	}

	expected := []net.IP{}
	expected = append(expected, unsortedAddrs[2])
	expected = append(expected, unsortedAddrs[1])
	expected = append(expected, unsortedAddrs[0])

	slices.SortStableFunc(unsortedAddrs, func(a, b net.IP) int {
		return rankIPAddr(b) - rankIPAddr(a)
	})

	if !reflect.DeepEqual(unsortedAddrs, expected) {
		t.Errorf("expected %v, got %v", expected, unsortedAddrs)
	}
}
