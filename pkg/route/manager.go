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
	"context"
	"fmt"
	"net"
	"sync"
)

// Manager handles static route operations.
type Manager interface {
	// GetRoutes returns all routes currently in the system.
	GetRoutes() ([]*Route, error)

	// FindBestRoute finds the best route for a destination IP.
	FindBestRoute(dst net.IP) (*Route, error)

	// AddRoute adds a static route.
	// Throws a 'file exists' error if the route already exists,
	// use os.IsExist to check for this case.
	AddRoute(route *Route) error

	// RemoveRoute removes a static route.
	RemoveRoute(route *Route) error

	// Cleanup removes all routes added by this manager.
	Cleanup() error

	// Close closes the manager and releases resources.
	Close() error

	// GetDefaultGateway4 returns the IPv4 default gateway (nil if not set).
	GetDefaultGateway4() net.IP

	// GetDefaultGateway6 returns the IPv6 default gateway (nil if not set).
	GetDefaultGateway6() net.IP

	// WaitDefaultGateway waits for the default gateway to be set.
	WaitDefaultGateway(v4, v6 bool) <-chan struct{}
}

type platformBackend interface {
	applyRoute(rt *Route) error
	deleteRoute(rt *Route) error
	loadRoutes() ([]*Route, error)
	startWatch(ctx context.Context, onChange func(), v4RouteTable, v6RouteTable *Table) error
	close() error
}

type baseManager struct {
	ctx             context.Context
	cancel          context.CancelFunc
	routeTableV4    *Table
	routeTableV6    *Table
	trackedRoutesV4 sync.Map
	trackedRoutesV6 sync.Map
	defGwCond       *sync.Cond
	backend         platformBackend

	findBestRouteFn func(dst net.IP) (*Route, error)
	waitDefaultGwFn func(v4, v6 bool) <-chan struct{}
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

// NewManager creates a new route manager for the current platform.
func NewManager(ctx context.Context) (Manager, error) {
	return newBaseManager(ctx)
}

func newBaseManager(ctx context.Context) (*baseManager, error) {
	mCtx := context.Background()
	if ctx != nil {
		mCtx = ctx
	}
	mCtx, cancel := context.WithCancel(mCtx)
	bm := &baseManager{
		routeTableV4: NewTable(FamilyInet),
		routeTableV6: NewTable(FamilyInet6),
		ctx:          mCtx,
		cancel:       cancel,
		defGwCond:    sync.NewCond(&sync.Mutex{}),
	}

	backend, err := newBackend()
	if err != nil {
		return nil, err
	}

	type routeFinder interface {
		findBestRoute(dst net.IP) (*Route, error)
	}
	rf, ok := backend.(routeFinder)
	if ok {
		bm.findBestRouteFn = rf.findBestRoute
	}

	bm.backend = backend

	if err := bm.initFromOS(); err != nil {
		bm.Close()
		return nil, err
	}
	return bm, nil
}

func (m *baseManager) initFromOS() error {
	routes, err := m.backend.loadRoutes()
	if err != nil {
		return err
	}
	for _, rt := range routes {
		table := m.routeTableForFamily(rt.Family())
		if table == nil {
			continue
		}
		table.Insert(rt)
	}
	return m.backend.startWatch(m.ctx, m.onRouteChange, m.routeTableV4, m.routeTableV6)
}

func (m *baseManager) onRouteChange() {
	m.defGwCond.Broadcast()
}

func (m *baseManager) trackedRoutesForRoute(rt *Route) *sync.Map {
	if rt.Is4() {
		return &m.trackedRoutesV4
	}
	return &m.trackedRoutesV6
}

func (m *baseManager) routeTableForFamily(family int) *Table {
	switch family {
	case FamilyInet:
		return m.routeTableV4
	case FamilyInet6:
		return m.routeTableV6
	}
	return nil
}

func (m *baseManager) getFindBestRouteFn() func(dst net.IP) (*Route, error) {
	if m.findBestRouteFn != nil {
		return m.findBestRouteFn
	}
	return m.FindBestRoute
}

// AddRouteToBestRoute finds the best route for a destination IP and adds a static route to it.
func (m *baseManager) AddRouteToBestRoute(destination *net.IPNet) error {
	route, err := m.getFindBestRouteFn()(destination.IP)
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
	err = m.AddRoute(route)
	if err != nil {
		return fmt.Errorf("failed to add route for %s: %w", destination.String(), err)
	}
	return nil
}

func (m *baseManager) AddRoute(rt *Route) error {
	if rt.Gateway == nil {
		bestRoute, err := m.getFindBestRouteFn()(rt.Destination.IP)
		if err != nil {
			return err
		}
		if bestRoute.IsDirectlyConnected() {
			return fmt.Errorf("%w: %s via %s (%s)", ErrDirectlyConnected, rt.Destination.IP.String(), bestRoute.LinkAddr.String(), bestRoute.Interface)
		}
		rt.Gateway = bestRoute.Gateway
		rt.Interface = bestRoute.Interface
	}
	if err := m.backend.applyRoute(rt); err != nil {
		return err
	}
	trackedRoutes := m.trackedRoutesForRoute(rt)
	trackedRoutes.Store(rt.String(), rt)
	return nil
}

func (m *baseManager) RemoveRoute(rt *Route) error {
	if err := m.backend.deleteRoute(rt); err != nil {
		return err
	}
	trackedRoutes := m.trackedRoutesForRoute(rt)
	trackedRoutes.Delete(rt.String())
	return nil
}

func (m *baseManager) Cleanup() error {
	var err error
	e := m.cleanup(&m.trackedRoutesV4)
	if e != nil {
		err = wrapError(err, e, "failed to cleanup tracked routes v4")
	}
	e = m.cleanup(&m.trackedRoutesV6)
	if e != nil {
		err = wrapError(err, e, "failed to cleanup tracked routes v6")
	}
	return err
}

func (m *baseManager) cleanup(trackedRoutes *sync.Map) error {
	var routesToRemove []*Route
	trackedRoutes.Range(func(key, value interface{}) bool {
		if rt, ok := value.(*Route); ok {
			routesToRemove = append(routesToRemove, rt)
		}
		return true
	})

	var errReturn error
	for _, rt := range routesToRemove {
		err := m.RemoveRoute(rt)
		if err != nil {
			errReturn = wrapError(errReturn, err, fmt.Sprintf("failed to cleanup route %s", rt.String()))
		}
	}
	return errReturn
}

func (m *baseManager) FindBestRoute(dst net.IP) (*Route, error) {
	if m.findBestRouteFn != nil {
		// we have an override for finding the best route
		rt, err := m.findBestRouteFn(dst)
		if err != nil {
			return nil, err
		}
		// create hard copy of the route
		rtCopy := *rt
		return &rtCopy, nil
	}

	if dst == nil {
		return nil, fmt.Errorf("destination IP is nil")
	}

	isV4 := dst.To4() != nil
	if isV4 {
		dst = dst.To4()
	}
	if !isV4 {
		dst = dst.To16()
	}
	if dst == nil {
		return nil, fmt.Errorf("invalid destination IP")
	}

	family := FamilyInet6
	if isV4 {
		family = FamilyInet
	}

	table := m.routeTableForFamily(family)
	if table == nil {
		return nil, fmt.Errorf("no route table for family %d", family)
	}

	rt := table.Lookup(dst)
	// create hard copy of the route
	rtCopy := *rt
	return &rtCopy, nil
}

func (m *baseManager) GetDefaultGateway4() net.IP {
	defaultRoute := m.routeTableV4.DefaultRoute()
	if defaultRoute == nil {
		return nil
	}
	return defaultRoute.Gateway
}

func (m *baseManager) GetDefaultGateway6() net.IP {
	defaultRoute := m.routeTableV6.DefaultRoute()
	if defaultRoute == nil {
		return nil
	}
	return defaultRoute.Gateway
}

func (m *baseManager) WaitDefaultGateway(v4, v6 bool) <-chan struct{} {
	if m.waitDefaultGwFn != nil {
		return m.waitDefaultGwFn(v4, v6)
	}
	ch := make(chan struct{})
	go func() {
		m.waitDefaultGateway(v4, v6)
		close(ch)
	}()
	return ch
}

func (m *baseManager) waitDefaultGateway(v4, v6 bool) {
	m.defGwCond.L.Lock()
	for {
		select {
		case <-m.ctx.Done():
			return
		default:
		}
		if v4 && m.GetDefaultGateway4() == nil {
			m.defGwCond.Wait()
			continue
		}
		if v6 && m.GetDefaultGateway6() == nil {
			m.defGwCond.Wait()
			continue
		}
		break
	}
	m.defGwCond.L.Unlock()
}

func (m *baseManager) GetRoutes() ([]*Route, error) {
	return m.backend.loadRoutes()
}

func (m *baseManager) Close() error {
	if m.cancel != nil {
		m.cancel()
	}
	err := m.backend.close()
	m.defGwCond.Broadcast()
	return err
}
