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

//go:build !darwin && !linux && !windows

package route

import (
	"context"
	"fmt"
	"net"
)

// Stub implementations for non-macOS platforms.
// These will be implemented when adding support for Linux and Windows.
func newManager(ctx context.Context) (Manager, error) {
	return &stubManager{}, nil
}

// Stub implementation for GetAdapterIP on non-macOS platforms.
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
