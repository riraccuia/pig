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

package route

import (
	"errors"
	"fmt"
	"net"
)

var (
	ErrDirectlyConnected = errors.New("directly connected")
)

const (
	// FamilyInet and FamilyInet6 identify route address families for the PATRICIA table.
	// Values match unix.AF_INET / unix.AF_INET6 on Darwin and Linux.
	FamilyInet  = 2
	FamilyInet6 = 30
)

// Route represents a static route entry
type Route struct {
	Destination *net.IPNet
	Gateway     net.IP
	Interface   string
	LinkAddr    net.HardwareAddr
}

// Is4 returns true if the route is an IPv4 route
func (r *Route) Is4() bool {
	return r.Destination.IP.To4() != nil
}

// Family returns the family of the route.
// If the route is not IPv4 or IPv6, it returns -1.
// Otherwise, the family is one of FamilyInet or FamilyInet6.
func (r *Route) Family() int {
	if r.Destination.IP.To4() != nil {
		return FamilyInet
	}
	if r.Destination.IP.To16() != nil {
		return FamilyInet6
	}
	return -1
}

func (r *Route) IsDirectlyConnected() bool {
	if r.Gateway != nil && !r.Gateway.Equal(net.IPv4zero) && !r.Gateway.Equal(net.IPv6zero) {
		return false
	}
	return r.LinkAddr != nil
}

func (r Route) HasGateway() bool {
	return r.Gateway != nil && !r.Gateway.Equal(net.IPv4zero) && !r.Gateway.Equal(net.IPv6zero)
}

// String returns a unique string representation of the route
func (r Route) String() string {
	key := r.Destination.String() + "|" + r.Interface
	if r.Gateway != nil {
		key += "|" + r.Gateway.String()
	}
	return key
}

func (r *Route) ParseDestination(destCIDR string) error {
	_, ipNet, err := net.ParseCIDR(destCIDR)
	if err != nil {
		return fmt.Errorf("failed to parse destination CIDR: %w", err)
	}
	r.Destination = ipNet
	return nil
}
