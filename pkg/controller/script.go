package controller

import (
	"strings"

	"github.com/riraccuia/pig/pkg/client"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/script"
)

func (c *Controller) executeClientScript(proto config.TransportType, adapter common.TunnelAdapter, eventContext *client.EventContext) {
	if c.scriptExecutor == nil {
		return
	}
	switch eventContext.Event {
	case client.EventConnected, client.EventDisconnected, client.EventStopped:
	default:
		// not applicable for this event
		return
	}
	remoteAddr := ""
	if eventContext.Conn != nil {
		remoteAddr = strings.Split(eventContext.Conn.RemoteAddr().String(), ":")[0]
	}
	sctx := script.ScriptContext{
		TunnelName:  adapter.Name(),
		TunnelIndex: adapter.Index(),
		RemoteAddr:  remoteAddr,
		NatAddr:     "", // No NAT address in client mode
		TunnelProto: string(proto),
	}
	if eventContext.Event == client.EventConnected {
		c.scriptExecutor.ExecuteStartScript(sctx)
		return
	}
	c.scriptExecutor.ExecuteStopScript(sctx)
}
