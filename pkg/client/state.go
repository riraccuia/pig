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

package client

// State represents the connection state of a tunnel client. Use int32 for atomic support.
type State int32

const (
	StateDisconnected State = iota
	StateConnecting
	StateConnected
	StateStopped
	StateConnectionFailed
)

var StateToString = map[State]string{
	StateDisconnected:     "disconnected",
	StateConnecting:       "connecting",
	StateConnected:        "connected",
	StateStopped:          "stopped",
	StateConnectionFailed: "connection failed",
}

func (s State) String() string {
	return StateToString[s]
}

// updateStateFromEvent updates the client state based on the event.
// It also updates the peer address if the event is EventConnected.
func (c *Client) updateStateFromEvent(event *EventContext) {
	switch event.State {
	case StateConnected:
		c.state.Store(int32(event.State))
		if event.Conn != nil {
			c.peerAddr.Store(atomicAddr{Addr: event.Conn.RemoteAddr()})
		}
	case StateDisconnected, StateStopped, StateConnectionFailed:
		c.state.Store(int32(event.State))
	}
}

// State returns the current connection state. Safe to call from any goroutine.
func (c *Client) State() State {
	return State(c.state.Load())
}
