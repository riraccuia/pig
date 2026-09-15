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

package script

import "github.com/riraccuia/pig/pkg/common"

var (
	EnvEventName = common.EnvVar{
		VarName:     "PIG_EVENT_NAME",
		Description: "Name of the event",
	}
	EnvTunnelName = common.EnvVar{
		VarName:     "PIG_TUN_NAME",
		Description: "Name of the tunnel",
	}
	EnvAdapterName = common.EnvVar{
		VarName:     "PIG_ADAPTER_NAME",
		Description: "Name of the adapter",
	}
	EnvAdapterIndex = common.EnvVar{
		VarName:     "PIG_ADAPTER_INDEX",
		Description: "Index of the adapter",
	}
	EnvRemoteAddr = common.EnvVar{
		VarName:     "PIG_REMOTE_ADDR",
		Description: "Remote address",
	}
	EnvNatAddr = common.EnvVar{
		VarName:     "PIG_NAT_ADDR",
		Description: "NAT address",
	}
	EnvTunnelProto = common.EnvVar{
		VarName:     "PIG_TUNNEL_PROTO",
		Description: "Transport protocol used for the tunnel",
	}
)

var EnvVars = []common.EnvVar{
	EnvEventName,
	EnvTunnelName,
	EnvAdapterName,
	EnvAdapterIndex,
	EnvRemoteAddr,
	EnvNatAddr,
	EnvTunnelProto,
}
