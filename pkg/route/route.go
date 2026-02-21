package route

import (
	"context"
	"fmt"
	"net"
)

// Route represents a static route entry
type Route struct {
	Destination *net.IPNet
	Gateway     net.IP
	Interface   string
	LinkAddr    net.HardwareAddr
}

// Is4 returns true if the route is an IPv4 route
func (r Route) Is4() bool {
	return r.Destination.IP.To4() != nil
}

func (r Route) IsDirectlyConnected() bool {
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

type Manager struct {
	manager
}

// manager handles static route operations
type manager interface {
	// GetRoutes returns all routes currently in the system
	GetRoutes() ([]*Route, error)

	// FindBestRoute finds the best route for a destination IP
	FindBestRoute(dst net.IP) (*Route, error)

	// AddRoute adds a static route
	AddRoute(route *Route) error

	// RemoveRoute removes a static route
	RemoveRoute(route *Route) error

	// Cleanup removes all routes added by this manager
	Cleanup() error

	// Close closes the manager and releases resources
	Close() error

	// GetDefaultGateway4 returns the IPv4 default gateway (nil if not set)
	GetDefaultGateway4() net.IP

	// GetDefaultGateway6 returns the IPv6 default gateway (nil if not set)
	GetDefaultGateway6() net.IP

	// WaitDefaultGateway waits for the default gateway to be set
	WaitDefaultGateway(v4, v6 bool) <-chan struct{}
}

// AddRouteToBestRoute finds the best route for a destination IP and adds a static route to it
func (m *Manager) AddRouteToBestRoute(destination *net.IPNet) error {
	route, err := m.manager.FindBestRoute(destination.IP)
	if err != nil {
		return fmt.Errorf("failed to find best route for %s: %w", destination.IP.String(), err)
	}
	if route.IsDirectlyConnected() {
		return fmt.Errorf("%s is directly connected via %s (%s)", destination.IP.String(), route.LinkAddr.String(), route.Interface)
	}
	if !route.HasGateway() {
		return fmt.Errorf("cannot route %s: no suitable gateway found", destination.IP.String())
	}
	route.Destination = destination
	err = m.manager.AddRoute(route)
	if err != nil {
		return fmt.Errorf("failed to add route for %s: %w", destination.String(), err)
	}
	return nil
}

// NewManager creates a new route manager for the current platform
func NewManager(ctx context.Context) (*Manager, error) {
	manager, err := newManager(ctx)
	if err != nil {
		return nil, err
	}
	return &Manager{manager: manager}, nil
}

func wrapError(prev error, err error, label string) error {
	if err != nil && prev != nil {
		return fmt.Errorf("%w, %s: %w", prev, label, err)
	}
	if err != nil && prev == nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	if err == nil && prev != nil {
		return prev
	}
	return nil
}
