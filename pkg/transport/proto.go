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

package transport

type ICEProtocolDefinition struct {
	Network     string // the network type, e.g. "tcp", "udp", etc.
	Protocol    string // the pig protocol name, e.g. "ws", "quic", "tls", etc.
	ComponentID int    // the component id, e.g. 3, 4, 5, etc.
}

var (
	ICEProtocolWS = ICEProtocolDefinition{
		Network:     "tcp",
		Protocol:    "ws",
		ComponentID: 3,
	}
	ICEProtocolQUIC = ICEProtocolDefinition{
		Network:     "udp",
		Protocol:    "quic",
		ComponentID: 4,
	}
	ICEProtocolDTLS = ICEProtocolDefinition{
		Network:     "udp",
		Protocol:    "dtls",
		ComponentID: 5,
	}
	ICEProtocolTLS = ICEProtocolDefinition{
		Network:     "tcp",
		Protocol:    "tls",
		ComponentID: 6,
	}
	ICEProtocolTLSInICMP = ICEProtocolDefinition{
		Network:     "icmp",
		Protocol:    "tls-in-icmp",
		ComponentID: 7,
	}
)

// a map of protocol definitions keyed by pig protocol name, e.g. "ws", "tls", "quic", etc.
var ICEProtocolDefinitionsByProtocol = map[string]ICEProtocolDefinition{
	ICEProtocolWS.Protocol:        ICEProtocolWS,
	ICEProtocolQUIC.Protocol:      ICEProtocolQUIC,
	ICEProtocolDTLS.Protocol:      ICEProtocolDTLS,
	ICEProtocolTLS.Protocol:       ICEProtocolTLS,
	ICEProtocolTLSInICMP.Protocol: ICEProtocolTLSInICMP,
}

// a map of protocol definitions keyed by component id, e.g. 3, 4, 5, etc.
var ICEProtocolDefinitionsByComponentID = map[int]ICEProtocolDefinition{
	ICEProtocolWS.ComponentID:        ICEProtocolWS,
	ICEProtocolQUIC.ComponentID:      ICEProtocolQUIC,
	ICEProtocolDTLS.ComponentID:      ICEProtocolDTLS,
	ICEProtocolTLS.ComponentID:       ICEProtocolTLS,
	ICEProtocolTLSInICMP.ComponentID: ICEProtocolTLSInICMP,
}
