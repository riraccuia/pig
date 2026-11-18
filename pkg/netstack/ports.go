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

import "math/rand/v2"

// Dynamic and private port range (RFC 6335 §6).
const (
	ephemeralPortFirst = 49152
	ephemeralPortCount = 65536 - ephemeralPortFirst
)

// allocatePort returns a free ephemeral port, starting the search at a random
// offset. busy reports whether a port is already taken.
func allocatePort(busy func(port uint16) bool) (uint16, bool) {
	start := rand.IntN(ephemeralPortCount)
	for i := range ephemeralPortCount {
		port := uint16(ephemeralPortFirst + (start+i)%ephemeralPortCount)
		if !busy(port) {
			return port, true
		}
	}
	return 0, false
}
