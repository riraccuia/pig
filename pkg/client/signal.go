package client

import (
	"github.com/riraccuia/pig/pkg/transport"
)

// Event represents the current event type of the client
type Event int

const (
	// EventUnknown indicates an unknown event
	EventUnknown Event = iota
	// EventStopped indicates the client has stopped
	EventStopped
	// EventConnected indicates the client is connected to the server
	EventConnected
	// EventDisconnected indicates the client has disconnected from the server
	EventDisconnected
	// EventConnectionFailed indicates the client has failed to connect to the server
	EventConnectionFailed
)

// EventMap is a map of event types to their string representations
var EventMap = map[Event]string{
	EventUnknown:          "unknown",
	EventStopped:          "stopped",
	EventConnected:        "connected",
	EventDisconnected:     "disconnected",
	EventConnectionFailed: "connection failed",
}

func (e Event) String() string {
	return EventMap[e]
}

// EventContext represents a client event that is sent over the event channel
type EventContext struct {
	Event Event
	Conn  transport.Conn
	Error error // Error that occurred during the event
}

func (c *Client) signalEvent(event *EventContext) {
	select {
	case c.events <- event:
		return
	default:
		c.logger.Errorf("Events channel full, dropping event %s", event.Event)
	}
}
