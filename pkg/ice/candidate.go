package ice

import (
	"net"

	"github.com/riraccuia/pig/pkg/ice/message"
)

func CandidateFrom(network string, componentID int, ip net.IP, srcPort int) message.ICECandidate {
	cType := message.ICECandidateTypeHost
	cPriority := message.CalculateHostPriority()
	if !ip.IsPrivate() {
		cType = message.ICECandidateTypeSrflx
		cPriority = message.CalculateSrflxPriority()
	}
	return message.ICECandidate{
		Foundation:  message.GenerateFoundation(ip.String()),
		ComponentID: componentID,
		Priority:    cPriority,
		Protocol:    network,
		Address:     ip.String(),
		Port:        srcPort,
		Type:        cType,
	}
}
