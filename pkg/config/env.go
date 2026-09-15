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

package config

import (
	"github.com/riraccuia/pig/pkg/common"
)

var (
	EnvToken = common.EnvVar{
		VarName:     "PIG_TOKEN",
		Description: "JWT token string to use for client authentication",
	}
	EnvSTUN = common.EnvVar{
		VarName:     "PIG_STUN",
		Description: "STUN server for NAT traversal",
	}
	EnvMQTTBroker = common.EnvVar{
		VarName:     "PIG_MQTT_BROKER",
		Description: "MQTT broker for NAT traversal ICE signaling",
	}
	EnvMQTTClientID = common.EnvVar{
		VarName:     "PIG_MQTT_CLIENT_ID",
		Description: "MQTT client identifier for the signaling broker",
	}
	EnvMQTTUsername = common.EnvVar{
		VarName:     "PIG_MQTT_USERNAME",
		Description: "MQTT username for the signaling broker",
	}
	EnvMQTTPassword = common.EnvVar{
		VarName:     "PIG_MQTT_PASSWORD",
		Description: "MQTT password for the signaling broker",
	}
)

var EnvVars = []common.EnvVar{
	EnvToken,
	EnvSTUN,
	EnvMQTTBroker,
	EnvMQTTClientID,
	EnvMQTTUsername,
	EnvMQTTPassword,
}
