package ice

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"slices"

	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/transport"
)

type ConnectPath struct {
	LocalNet   *net.IPNet
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	Protocol   transport.ICEProtocolDefinition
}

func GetConnectPaths(ctx context.Context, opts *signaling.Options, addr string, pigProtos []transport.ICEProtocolDefinition) (cp []*ConnectPath, err error) {
	localNets, localIps, err := getLocalNetworks()
	if err != nil {
		return nil, err
	}

	var offerCandidates, answerCandidates []message.ICECandidate

	for _, tr := range pigProtos {
		// local candidates
		for i, localIp := range localIps {
			srcPort := rand.Intn(65535-1024) + 1024
			localAddr := AddressFrom(tr.Network, localIp, srcPort)
			cp = append(cp, &ConnectPath{
				LocalNet:  localNets[i],
				LocalAddr: localAddr,
				Protocol:  tr,
			})
			offerCandidates = append(offerCandidates, CandidateFrom(tr.Network, tr.ComponentID, localIp, srcPort))
		}
		// reflexive candidate
		localAddr := AddressFrom(tr.Network, net.IPv4zero, 0)
		// Get mapped endpoint
		mappedIP, mappedPort, err := PerformSTUNQuery(opts.Logger, opts.STUNServer, localAddr)
		if err != nil {
			return nil, fmt.Errorf("STUN query failed: %w", err)
		}
		cp = append(cp, &ConnectPath{
			LocalAddr: localAddr,
			Protocol:  tr,
		})
		offerCandidates = append(offerCandidates, CandidateFrom(tr.Network, tr.ComponentID, mappedIP, mappedPort))
	}

	answerCandidates, err = signaling.GatherICECandidates(ctx, opts, addr, offerCandidates)
	if err != nil {
		return
	}

	opts.Logger.Debugf("answerCandidates: %v", answerCandidates)

	for _, candidate := range answerCandidates {
		targetIP := net.ParseIP(candidate.Address)
		for _, connect := range cp {
			if connect.Protocol.Network != candidate.Protocol {
				continue
			}
			if connect.Protocol.ComponentID != candidate.ComponentID {
				continue
			}
			if connect.LocalNet != nil && !connect.LocalNet.Contains(targetIP) {
				continue
			}
			connect.RemoteAddr = AddressFrom(connect.Protocol.Network, targetIP, candidate.Port)
		}
	}

	// remove from the connectMap the ones that do not have a remote address
	cp = slices.DeleteFunc(cp, func(c *ConnectPath) bool {
		return c.RemoteAddr == nil
	})

	opts.Logger.Debugf("connectPaths: %v", cp)

	if len(cp) == 0 {
		err = fmt.Errorf("no valid candidates found")
		return
	}

	return
}

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

func AddressFrom(network string, ip net.IP, port int) (addr net.Addr) {
	if port == 0 {
		port = rand.Intn(65535-1024) + 1024
	}
	switch network {
	case "udp":
		addr = &net.UDPAddr{IP: ip, Port: port}
	case "tcp":
		addr = &net.TCPAddr{IP: ip, Port: port}
	}
	return
}
