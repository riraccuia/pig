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

package netstack

import "errors"

var (
	ErrConnectionRefused = errors.New("netstack: connection refused")
	ErrConnectionReset   = errors.New("netstack: connection reset by peer")
	ErrTimeout           = errors.New("netstack: connection timed out")
	ErrNotConnected      = errors.New("netstack: connection is not open for writing")
	ErrNoLocalAddress    = errors.New("netstack: no local address for this address family")
	ErrPortsExhausted    = errors.New("netstack: no ephemeral ports available")
	ErrAddressInUse      = errors.New("netstack: address already in use")
	ErrBacklogFull       = errors.New("netstack: listener backlog full")
	ErrMessageTooLong    = errors.New("netstack: message too long")
)
