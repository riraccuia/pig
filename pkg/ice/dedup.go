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

package ice

import (
	"fmt"

	"github.com/riraccuia/pig/pkg/ice/message"
)

func dedupCandidates(candidates []message.ICECandidate) []message.ICECandidate {
	seen := map[string]struct{}{}
	out := make([]message.ICECandidate, 0, len(candidates))
	for _, c := range candidates {
		key := candidateKey(c)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
	}
	return out
}

func dedupConnectPaths(paths []*ConnectPath) []*ConnectPath {
	seen := make(map[string]struct{}, len(paths))
	out := make([]*ConnectPath, 0, len(paths))
	for _, p := range paths {
		if p == nil || p.LocalAddr == nil || p.RemoteAddr == nil {
			continue
		}
		key := fmt.Sprintf("%s|%s|%s", p.Protocol.Network, p.LocalAddr.String(), p.RemoteAddr.String())
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, p)
	}
	return out
}

func candidateKey(c message.ICECandidate) string {
	return fmt.Sprintf("%s|%d|%s|%d|%s", c.Protocol, c.ComponentID, c.Address, c.Port, c.Type)
}
