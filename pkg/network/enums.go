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

package network

const (
	ProtocolTCP    = 6
	ProtocolUDP    = 17
	ProtocolICMP   = 1
	ProtocolICMPv6 = 58
)

// ICMP types
const (
	ICMPTypeEchoRequest = 8
	ICMPTypeEchoReply   = 0

	ICMPv6TypeEchoRequest = 128
	ICMPv6TypeEchoReply   = 129
)
