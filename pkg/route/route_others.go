//go:build !darwin && !windows

package route

import (
	"context"
	"fmt"
	"net"
)

// Stub implementations for non-macOS platforms
// These will be implemented when adding support for Linux and Windows
func newManager(ctx context.Context) (manager, error) {
	return &stubManager{}, nil
}

// Stub implementation for GetAdapterIP on non-macOS platforms
type stubManager struct{}

func (s *stubManager) AddRoute(route *Route) error {
	return fmt.Errorf("route management not implemented for this platform")
}

func (s *stubManager) RemoveRoute(route *Route) error {
	return fmt.Errorf("route management not implemented for this platform")
}

func (s *stubManager) Cleanup() error {
	return fmt.Errorf("route management not implemented for this platform")
}

func (s *stubManager) GetRoutes() ([]*Route, error) {
	return nil, fmt.Errorf("route management not implemented for this platform")
}

func (s *stubManager) WaitDefaultGateway(v4, v6 bool) <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

func (s *stubManager) Close() error {
	return nil
}

func (s *stubManager) GetDefaultGateway4() net.IP {
	return nil
}

func (s *stubManager) GetDefaultGateway6() net.IP {
	return nil
}

func (s *stubManager) FindBestRoute(dst net.IP) (*Route, error) {
	return nil, fmt.Errorf("route management not implemented for this platform")
}
