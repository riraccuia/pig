package ice

import (
	"context"
	"fmt"
	"math/rand"
	"net"

	"github.com/riraccuia/pig/pkg/ice/conn"
	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/transport"
)

// Connect establishes a connection to a remote address using ICE.
// It returns the connection, the remote address, and any error that occurs.
// The srcPort parameter is the source port to use for the connection, if 0, a random port will be used.
// The dstPort parameter is the destination port to use for the connection.
// The addr parameter is the ip address to connect to.
// The network parameter is the network type to use for the connection, either "udp" or "tcp".
func Connect(ctx context.Context, opts *signaling.Options, srcPort, dstPort int, addr string, pigProto transport.ICEProtocolDefinition) (co net.Conn, remoteAddr net.Addr, err error) {
	if srcPort == 0 {
		// generate random port
		srcPort = rand.Intn(65535-1024) + 1024
	}

	var (
		localAddr net.Addr
	)
	switch pigProto.Network {
	case "udp":
		localAddr = &net.UDPAddr{IP: net.IPv4zero, Port: srcPort}
	case "tcp":
		localAddr = &net.TCPAddr{IP: net.IPv4zero, Port: srcPort}
	}

	// Get mapped endpoint
	mappedIP, mappedPort, err := PerformSTUNQuery(opts.Logger, opts.STUNServer, localAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("STUN query failed: %w", err)
	}

	offerCandidates, err := GetCandidates(opts.Logger, mappedIP, mappedPort, localAddr)
	if err != nil {
		return nil, nil, err
	}

	candidates, err := signaling.GatherICECandidates(ctx, opts, addr, offerCandidates)
	if err != nil {
		return nil, nil, err
	}

	opts.Logger.Debugf("candidates: %v", candidates)

	ic, err := selectCandidate(opts, candidates, pigProto.Network)
	if err != nil {
		return nil, nil, err
	}

	if opts.Logger != nil {
		opts.Logger.Debugf("ICE candidate selected: %s:%d", ic.Address, ic.Port)
		opts.Logger.Infof("Dialing [%s] %s -> %s:%d", pigProto.Network, localAddr.String(), ic.Address, ic.Port)
	}

	switch pigProto.Network {
	case "udp":
		remoteAddr = &net.UDPAddr{IP: net.ParseIP(ic.Address).To4(), Port: ic.Port}
		co, err = net.ListenUDP("udp4", localAddr.(*net.UDPAddr))
	case "tcp":
		remoteAddr = &net.TCPAddr{IP: net.ParseIP(ic.Address).To4(), Port: ic.Port}
		co, err = conn.DialTCP("tcp", localAddr.(*net.TCPAddr), remoteAddr.(*net.TCPAddr))
	}
	return co, remoteAddr, err
}

// selectCandidate returns the best candidate from an ICE message
// This is a simplified implementation that prioritizes srflx candidates
func selectCandidate(opts *signaling.Options, candidates []message.ICECandidate, protocol string) (*message.ICECandidate, error) {
	localNets, _, err := getLocalNetworks()
	if err != nil {
		return nil, err
	}

	if len(candidates) == 0 {
		return nil, fmt.Errorf("no candidates available")
	}

	for _, candidate := range candidates {
		if candidate.Protocol != protocol {
			continue
		}
		for _, localNet := range localNets {
			opts.Logger.Debugf("localNet: %s vs candidate: %s", localNet.String(), candidate.Address)
			if localNet.Contains(net.ParseIP(candidate.Address)) {
				return &candidate, nil
			}
		}
		if candidate.Type == message.ICECandidateTypeSrflx {
			return &candidate, nil
		}
	}

	// Fall back to any candidate
	candidate := candidates[0]
	return &candidate, nil
}

func getLocalNetworks() (ipNets []*net.IPNet, ips []net.IP, err error) {
	var interfaces []net.Interface
	interfaces, err = net.Interfaces()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	for _, iface := range interfaces {
		addresses, err := iface.Addrs()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get addresses: %w", err)
		}
		for _, address := range addresses {
			var (
				ip    net.IP
				ipNet *net.IPNet
			)
			ip, ipNet, err = net.ParseCIDR(address.String())
			if err != nil {
				continue
			}
			if ipNet.IP.IsLoopback() {
				continue
			}
			if ipNet.IP.To4() == nil {
				continue
			}
			ipNets = append(ipNets, ipNet)
			ips = append(ips, ip)
		}
	}
	return ipNets, ips, nil
}
