package ice

import (
	"net"
	"strconv"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/ice/message"
)

func GetCandidates(logger common.Logger, mappedIP net.IP, mappedPort int, listenAddr net.Addr) (candidates []message.ICECandidate, err error) {
	reflexiveCandidates, err := GetReflexiveCandidates(mappedIP, mappedPort, listenAddr)
	if err != nil {
		logger.Errorf("Failed to get reflexive candidates: %v", err)
		return
	}
	localCandidates, err := GetLocalCandidates(listenAddr.Network(), listenAddr.(*net.TCPAddr).Port)
	if err != nil {
		logger.Errorf("Failed to get local candidates: %v", err)
		return
	}
	return append(localCandidates, reflexiveCandidates...), nil
}

func GetLocalCandidates(proto string, portInt int) ([]message.ICECandidate, error) {
	hosts, err := GetLocalHosts()
	if err != nil {
		return nil, err
	}

	var localCandidates []message.ICECandidate
	for _, h := range hosts {
		localCandidates = append(localCandidates, message.ICECandidate{
			Foundation: message.GenerateFoundation(h),
			Priority:   message.CalculateHostPriority(),
			Protocol:   proto,
			Address:    h,
			Port:       portInt,
			Type:       message.ICECandidateTypeHost,
		})
	}
	return localCandidates, nil
}

func GetReflexiveCandidates(mappedIP net.IP, mappedPort int, localAddr net.Addr) ([]message.ICECandidate, error) {
	host, port, err := net.SplitHostPort(localAddr.String())
	if err != nil {
		return nil, err
	}
	portInt, err := strconv.Atoi(port)
	if err != nil {
		return nil, err
	}

	proto := localAddr.Network()

	ic := message.ICECandidate{
		Foundation:  message.GenerateFoundation(mappedIP.String()),
		Priority:    message.CalculateSrflxPriority(),
		Protocol:    proto,
		Address:     mappedIP.String(),
		Port:        mappedPort,
		Type:        message.ICECandidateTypeSrflx,
		RelatedAddr: host,
		RelatedPort: portInt,
	}

	return []message.ICECandidate{ic}, nil
}

func GetLocalHosts() (hosts []string, err error) {
	var interfaces []net.Interface
	interfaces, err = net.Interfaces()
	if err != nil {
		return
	}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		var addresses []net.Addr
		addresses, err = iface.Addrs()
		if err != nil {
			continue
		}
		for _, address := range addresses {
			var ip net.IP
			ip, _, err = net.ParseCIDR(address.String())
			if err != nil {
				continue
			}
			if ip.To4() != nil {
				hosts = append(hosts, ip.String())
			}
		}
	}
	err = nil
	return
}
