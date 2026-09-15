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

import "github.com/riraccuia/pig/pkg/stun"

func (pc *PathConnector) discoverNATType() int {
	result, err := stun.DiscoverNATBehavior(pc.opts.STUNServer, &stun.NATDiscoveryOptions{Scope: stun.DiscoveryFull})
	if err != nil {
		pc.opts.Logger.Errorf("failed to discover NAT behavior: %v", err)
	}
	if result != nil && result.IsBehindNAT() {
		pc.opts.Logger.Infof("NAT detected: %s", result.String())
	}
	return getNATType(result)
}

func getNATType(result *stun.NATDiscoveryResult) int {
	if result == nil {
		return 0
	}
	return int(result.Mapping)
}
