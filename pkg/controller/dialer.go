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

package controller

import (
	"context"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/network"
)

// newBypassDialer returns a net.Dialer that installs an underlay bypass route for
// each remote address the dialer is about to connect to (via ControlContext),
// then applies the usual socket options from network.NewDialer.
func (c *Controller) newBypassDialer(logger common.Logger, timeout time.Duration) *net.Dialer {
	dialer := network.NewDialer(timeout)
	controlFunc := dialer.Control
	dialer.ControlContext = func(ctx context.Context, network, address string, rawConn syscall.RawConn) error {
		if bypassIP := getDialIPFromAddress(address); bypassIP != nil {
			c.bypassTarget(logger, bypassIP)
		}
		if controlFunc != nil {
			// needed because network.NewDialer sets a Control method that would
			// be ignored if ControlContext is set
			return controlFunc(network, address, rawConn)
		}
		return nil
	}
	return dialer
}

func getDialIPFromAddress(address string) net.IP {
	addrPort, err := netip.ParseAddrPort(address)
	if err != nil {
		// Not a host:port remote (e.g. unix path); nothing to bypass.
		return nil
	}
	addr := addrPort.Addr()
	if !addr.IsValid() || addr.IsUnspecified() {
		return nil
	}
	return addr.AsSlice()
}
