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

package controller

import (
	"strings"

	"github.com/riraccuia/pig/pkg/client"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/script"
)

func (c *Controller) executeClientScript(proto config.TransportType, tunnel *client.Client, eventContext *client.EventContext) {
	if c.scriptExecutor == nil {
		return
	}
	switch eventContext.State {
	case client.StateConnected, client.StateDisconnected, client.StateStopped:
	default:
		// not applicable for this event
		return
	}
	remoteAddr := ""
	if eventContext.Conn != nil {
		remoteAddr = strings.Split(eventContext.Conn.RemoteAddr().String(), ":")[0]
	}
	sctx := script.ScriptContext{
		EventName:    client.StateToString[eventContext.State],
		TunnelName:   tunnel.Name(),
		AdapterName:  tunnel.GetAdapter().Name(),
		AdapterIndex: tunnel.GetAdapter().Index(),
		RemoteAddr:   remoteAddr,
		NatAddr:      "", // No NAT address in client mode
		TunnelProto:  string(proto),
	}
	c.scriptExecutor.ExecuteScript(sctx)
}
