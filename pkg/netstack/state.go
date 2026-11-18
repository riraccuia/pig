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

// State is a TCP connection state as defined in RFC 9293 §3.3.2.
type State int

const (
	StateClosed State = iota
	StateListen
	StateSynSent
	StateSynReceived
	StateEstablished
	StateFinWait1
	StateFinWait2
	StateCloseWait
	StateClosing
	StateLastAck
	StateTimeWait
)

var stateNames = [...]string{
	StateClosed:      "CLOSED",
	StateListen:      "LISTEN",
	StateSynSent:     "SYN-SENT",
	StateSynReceived: "SYN-RECEIVED",
	StateEstablished: "ESTABLISHED",
	StateFinWait1:    "FIN-WAIT-1",
	StateFinWait2:    "FIN-WAIT-2",
	StateCloseWait:   "CLOSE-WAIT",
	StateClosing:     "CLOSING",
	StateLastAck:     "LAST-ACK",
	StateTimeWait:    "TIME-WAIT",
}

func (s State) String() string {
	if s < 0 || int(s) >= len(stateNames) {
		return "UNKNOWN"
	}
	return stateNames[s]
}

// synchronized reports whether the handshake has completed (RFC 9293 §3.5.2).
func (s State) synchronized() bool {
	switch s {
	case StateEstablished, StateFinWait1, StateFinWait2, StateCloseWait,
		StateClosing, StateLastAck, StateTimeWait:
		return true
	}
	return false
}

// canSendData reports whether the application may still queue data.
func (s State) canSendData() bool {
	return s == StateEstablished || s == StateCloseWait
}

// canReceiveData reports whether segment text and FIN are processed (RFC 9293 §3.10.7.4).
func (s State) canReceiveData() bool {
	return s == StateEstablished || s == StateFinWait1 || s == StateFinWait2
}

// canTransmit reports whether queued data or our FIN may still go on the wire.
func (s State) canTransmit() bool {
	switch s {
	case StateEstablished, StateCloseWait, StateFinWait1, StateClosing, StateLastAck:
		return true
	}
	return false
}
