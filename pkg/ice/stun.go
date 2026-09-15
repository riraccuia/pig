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
	"net"

	"github.com/riraccuia/pig/pkg/stun"
)

// PerformSTUNQuery performs a STUN query to get the public endpoint.
func PerformSTUNQuery(stunClient *stun.Client, localAddr net.Addr) (mappedIP net.IP, mappedPort int, err error) {
	var result *stun.BindingResult
	// Perform STUN query to get our public endpoint
	switch localAddr.Network() {
	case "udp":
		//var port any = localAddr.(*net.UDPAddr).Port
		result, err = stunClient.QueryStunServerUDP(localAddr)
	case "tcp":
		result, err = stunClient.QueryStunServerTCP(localAddr)
	case "ip": // this is for icmp
		result, err = stunClient.QueryStunServerUDP(&net.UDPAddr{IP: nil, Port: 0})
	default:
		return nil, 0, fmt.Errorf("unsupported network type: %s", localAddr.Network())
	}
	if err != nil {
		return nil, 0, err
	}
	if result == nil {
		return nil, 0, nil
	}
	return result.IP, result.Port, nil
}
