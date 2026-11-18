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

// flightSize is FlightSize from RFC 5681 §2: sent but not yet acknowledged.
func (c *Conn) flightSize() uint32 {
	return c.sndNxt - c.sndUna
}

// usableWindow is how many more bytes may be sent, bounded by both the peer's
// receive window and the congestion window (RFC 5681 §3.1).
func (c *Conn) usableWindow() int {
	wnd := min(c.sndWnd, c.cc.cwnd)
	flight := c.flightSize()
	if flight >= wnd {
		return 0
	}
	return int(wnd - flight)
}
