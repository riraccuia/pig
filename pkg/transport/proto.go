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
)

// a map of protocol definitions keyed by pig protocol name, e.g. "ws", "tls", "quic", etc.
var ICEProtocolDefinitionsByProtocol = map[string]ICEProtocolDefinition{
	ICEProtocolWS.Protocol:   ICEProtocolWS,
	ICEProtocolQUIC.Protocol: ICEProtocolQUIC,
}

// a map of protocol definitions keyed by component id, e.g. 3, 4, 5, etc.
var ICEProtocolDefinitionsByComponentID = map[int]ICEProtocolDefinition{
	ICEProtocolWS.ComponentID:   ICEProtocolWS,
	ICEProtocolQUIC.ComponentID: ICEProtocolQUIC,
}
