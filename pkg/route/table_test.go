package route

import (
	"net"
	"slices"
	"syscall"
	"testing"
)

func TestRouteTableInsertAndLookup(t *testing.T) {
	type testCase struct {
		name           string
		family         int
		insertRoutes   []string
		lookupIP       string
		expectedRoute  string
		expectNilRoute bool
	}
	testCases := []testCase{
		// Normal cases
		{
			name:           "ipv4 default route",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"0.0.0.0/0"},
			lookupIP:       "1.2.3.4",
			expectedRoute:  "0.0.0.0/0",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 exact host route",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"10.0.0.42/32"},
			lookupIP:       "10.0.0.42",
			expectedRoute:  "10.0.0.42/32",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 longest prefix wins over default",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"0.0.0.0/0", "192.168.1.0/24"},
			lookupIP:       "192.168.1.50",
			expectedRoute:  "192.168.1.0/24",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 nested prefixes same aggregate",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"192.0.2.0/24", "192.0.2.0/25", "192.0.2.128/26"},
			lookupIP:       "192.0.2.190",
			expectedRoute:  "192.0.2.128/26",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 split default via two /1 routes",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"0.0.0.0/1", "128.0.0.0/1"},
			lookupIP:       "64.1.2.3",
			expectedRoute:  "0.0.0.0/1",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 split default upper half",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"0.0.0.0/1", "128.0.0.0/1"},
			lookupIP:       "200.1.2.3",
			expectedRoute:  "128.0.0.0/1",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 adjacent non-overlapping subnets",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"192.0.2.0/25", "192.0.2.128/25"},
			lookupIP:       "192.0.2.50",
			expectedRoute:  "192.0.2.0/25",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 specific subnet fallback to default",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"10.0.0.0/8", "0.0.0.0/0"},
			lookupIP:       "8.8.8.8",
			expectedRoute:  "0.0.0.0/0",
			expectNilRoute: false,
		},
		{
			name:           "ipv6 default route",
			family:         syscall.AF_INET6,
			insertRoutes:   []string{"::/0"},
			lookupIP:       "2001:db8::1",
			expectedRoute:  "::/0",
			expectNilRoute: false,
		},
		{
			name:           "ipv6 prefix match",
			family:         syscall.AF_INET6,
			insertRoutes:   []string{"2001:db8::/32", "::/0"},
			lookupIP:       "2001:db8:1::99",
			expectedRoute:  "2001:db8::/32",
			expectNilRoute: false,
		},
		{
			name:           "ipv6 exact host route",
			family:         syscall.AF_INET6,
			insertRoutes:   []string{"2001:db8::42/128"},
			lookupIP:       "2001:db8::42",
			expectedRoute:  "2001:db8::42/128",
			expectNilRoute: false,
		},
		{
			name:           "ipv6 nested prefixes same aggregate",
			family:         syscall.AF_INET6,
			insertRoutes:   []string{"2001:db8::/32", "2001:db8:1::/48", "2001:db8:1:1::/64"},
			lookupIP:       "2001:db8:1:1::99",
			expectedRoute:  "2001:db8:1:1::/64",
			expectNilRoute: false,
		},
		// Edge cases
		{
			name:           "ipv4 empty table",
			family:         syscall.AF_INET,
			insertRoutes:   nil,
			lookupIP:       "1.2.3.4",
			expectedRoute:  "",
			expectNilRoute: true,
		},
		{
			name:           "ipv6 empty table",
			family:         syscall.AF_INET6,
			insertRoutes:   nil,
			lookupIP:       "2001:db8::1",
			expectedRoute:  "",
			expectNilRoute: true,
		},
		{
			name:           "ipv4 no matching route without default",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"10.0.0.0/8"},
			lookupIP:       "192.168.1.1",
			expectedRoute:  "",
			expectNilRoute: true,
		},
		{
			name:           "ipv6 address on ipv4 table",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"0.0.0.0/0"},
			lookupIP:       "2001:db8::1",
			expectedRoute:  "",
			expectNilRoute: true,
		},
		{
			name:           "ipv4 address on ipv6 table",
			family:         syscall.AF_INET6,
			insertRoutes:   []string{"::/0"},
			lookupIP:       "1.2.3.4",
			expectedRoute:  "",
			expectNilRoute: true,
		},
		{
			name:           "ipv4 lookup subnet network address",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"192.0.2.0/24"},
			lookupIP:       "192.0.2.0",
			expectedRoute:  "192.0.2.0/24",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 lookup subnet broadcast address",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"192.0.2.0/24"},
			lookupIP:       "192.0.2.255",
			expectedRoute:  "192.0.2.0/24",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 prefix boundary last address of shorter route",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"192.0.2.0/25", "192.0.2.0/24"},
			lookupIP:       "192.0.2.127",
			expectedRoute:  "192.0.2.0/25",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 prefix boundary first address of sibling route",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"192.0.2.0/25", "192.0.2.128/25"},
			lookupIP:       "192.0.2.128",
			expectedRoute:  "192.0.2.128/25",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 host route beats covering subnet",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"10.0.0.0/8", "10.0.0.99/32"},
			lookupIP:       "10.0.0.99",
			expectedRoute:  "10.0.0.99/32",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 many overlapping routes same destination",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"0.0.0.0/0", "192.0.2.0/24", "192.0.2.0/25", "192.0.2.32/27", "192.0.2.48/30", "192.0.2.49/32"},
			lookupIP:       "192.0.2.49",
			expectedRoute:  "192.0.2.49/32",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 many overlapping routes with same network id, longest prefix wins",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"0.0.0.0/0", "192.0.2.0/24", "192.0.2.0/25", "192.0.2.0/26", "192.0.2.0/27", "192.0.2.0/28", "192.0.2.0/29", "192.0.2.0/30", "192.0.2.0/31", "192.0.2.0/32"},
			lookupIP:       "192.0.2.0",
			expectedRoute:  "192.0.2.0/32",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 os-like batch with default lookup unlisted address in subnet",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"0.0.0.0/0", "127.0.0.0/8", "127.0.0.1/32", "169.254.0.0/16", "192.168.2.0/24", "192.168.2.134/32", "192.168.2.205/32", "192.168.2.245/32"},
			lookupIP:       "192.168.2.202",
			expectedRoute:  "192.168.2.0/24",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 multiple host routes same subnet lookup unlisted address",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"192.168.2.0/24", "192.168.2.134/32", "192.168.2.205/32", "192.168.2.245/32"},
			lookupIP:       "192.168.2.202",
			expectedRoute:  "192.168.2.0/24",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 host route inserted before covering subnet lookup unlisted address",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"192.168.2.134/32", "192.168.2.0/24"},
			lookupIP:       "192.168.2.202",
			expectedRoute:  "192.168.2.0/24",
			expectNilRoute: false,
		},
		{
			name:           "ipv4 os-like batch lookup listed host after multiple host inserts",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"0.0.0.0/0", "127.0.0.0/8", "127.0.0.1/32", "169.254.0.0/16", "192.168.2.0/24", "192.168.2.134/32", "192.168.2.205/32", "192.168.2.245/32"},
			lookupIP:       "192.168.2.134",
			expectedRoute:  "192.168.2.134/32",
			expectNilRoute: false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			tree := NewTable(testCase.family)
			for _, r := range testCase.insertRoutes {
				_, ipNet, err := net.ParseCIDR(r)
				if err != nil {
					t.Fatalf("Failed to parse CIDR: %v", err)
				}
				tree.Insert(&Route{
					Destination: ipNet,
				})
			}
			route := tree.Lookup(net.ParseIP(testCase.lookupIP))
			if testCase.expectNilRoute && route == nil {
				return
			}
			if testCase.expectNilRoute && route != nil {
				t.Errorf("Expected nil route for %s, got %s", testCase.lookupIP, route.Destination.String())
				return
			}
			if route == nil {
				t.Errorf("Expected route %s for %s, got nil", testCase.expectedRoute, testCase.lookupIP)
				return
			}
			if route.Destination.String() != testCase.expectedRoute {
				t.Errorf("Expected route %s, got %s", testCase.expectedRoute, route.Destination.String())
				return
			}
		})
	}
}

func TestRouteTableRemove(t *testing.T) {
	type testCase struct {
		name           string
		family         int
		insertRoutes   []string
		removeRoute    string
		expectedRoutes []string
		expectDeleted  bool
	}
	testCases := []testCase{
		{
			name:           "ipv4 remove broader route leaves more specific routes",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"192.168.0.0/16", "192.168.2.0/25", "192.168.2.128/25"},
			removeRoute:    "192.168.0.0/16",
			expectedRoutes: []string{"192.168.2.0/25", "192.168.2.128/25"},
			expectDeleted:  true,
		},
		{
			name:           "ipv4 remove sole route empties table",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"10.0.0.0/8"},
			removeRoute:    "10.0.0.0/8",
			expectedRoutes: nil,
			expectDeleted:  true,
		},
		{
			name:           "ipv4 remove nested route keeps covering prefix",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"192.0.2.0/24", "192.0.2.0/25"},
			removeRoute:    "192.0.2.0/25",
			expectedRoutes: []string{"192.0.2.0/24"},
			expectDeleted:  true,
		},
		{
			name:           "ipv4 remove default route",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"0.0.0.0/0", "10.0.0.0/8"},
			removeRoute:    "0.0.0.0/0",
			expectedRoutes: []string{"10.0.0.0/8"},
			expectDeleted:  true,
		},
		{
			name:           "ipv4 remove default route when not present",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"10.0.0.0/8"},
			removeRoute:    "0.0.0.0/0",
			expectedRoutes: []string{"10.0.0.0/8"},
			expectDeleted:  false,
		},
		{
			name:           "ipv4 remove missing route",
			family:         syscall.AF_INET,
			insertRoutes:   []string{"10.0.0.0/8"},
			removeRoute:    "192.168.1.0/24",
			expectedRoutes: []string{"10.0.0.0/8"},
			expectDeleted:  false,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			tree := NewTable(testCase.family)
			for _, r := range testCase.insertRoutes {
				_, ipNet, err := net.ParseCIDR(r)
				if err != nil {
					t.Fatalf("Failed to parse CIDR: %v", err)
				}
				tree.Insert(&Route{
					Destination: ipNet,
				})
			}
			_, ipNet, err := net.ParseCIDR(testCase.removeRoute)
			if err != nil {
				t.Fatalf("Failed to parse CIDR: %v", err)
			}
			deleted := tree.Remove(&Route{
				Destination: ipNet,
			})
			if deleted != testCase.expectDeleted {
				t.Errorf("Expected route %s to be deleted, got %t", testCase.removeRoute, deleted)
				return
			}
			remainingRoutes := []string{}
			tree.Walk(func(r *Route) {
				remainingRoutes = append(remainingRoutes, r.Destination.String())
			})
			// sort the two slices
			slices.Sort(remainingRoutes)
			slices.Sort(testCase.expectedRoutes)
			if !slices.Equal(remainingRoutes, testCase.expectedRoutes) {
				t.Errorf("Expected remaining routes %v, got %v", testCase.expectedRoutes, remainingRoutes)
			}
		})
	}
}
