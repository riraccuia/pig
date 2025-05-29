package ice

import (
	"context"
	"fmt"
	"math/rand"
	"net"

	"github.com/riraccuia/pig/pkg/ice/conn"
	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/ice/signaling"
)

// Connect establishes a connection to a remote address using ICE.
// It returns the connection, the remote address, and any error that occurs.
// The srcPort parameter is the source port to use for the connection, if 0, a random port will be used.
// The dstPort parameter is the destination port to use for the connection.
// The addr parameter is the ip address to connect to.
// The network parameter is the network type to use for the connection, either "udp" or "tcp".
func Connect(ctx context.Context, opts *signaling.Options, srcPort, dstPort int, addr string, network string) (co net.Conn, remoteAddr net.Addr, err error) {
	if srcPort == 0 {
		// generate random port
		srcPort = rand.Intn(65535-1024) + 1024
	}

	var (
		localAddr  net.Addr
		targetAddr net.Addr
	)
	switch network {
	case "udp":
		targetAddr = &net.UDPAddr{IP: net.ParseIP(addr).To4(), Port: dstPort}
		localAddr = &net.UDPAddr{IP: net.IPv4zero, Port: srcPort}
	case "tcp":
		targetAddr = &net.TCPAddr{IP: net.ParseIP(addr).To4(), Port: dstPort}
		localAddr = &net.TCPAddr{IP: net.IPv4zero, Port: srcPort}
	}

	candidates, err := signaling.GatherICECandidates(ctx, opts, localAddr, targetAddr)
	if err != nil {
		return nil, nil, err
	}

	ic, err := selectCandidate(candidates, network)
	if err != nil {
		return nil, nil, err
	}

	if opts.Logger != nil {
		opts.Logger.Debugf("ICE candidate selected: %s:%d", ic.Address, ic.Port)
		opts.Logger.Infof("Dialing [%s] %s -> %s:%d", network, localAddr.String(), ic.Address, ic.Port)
	}

	switch network {
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
func selectCandidate(candidates []message.ICECandidate, protocol string) (*message.ICECandidate, error) {
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no candidates available")
	}

	// First look for srflx candidates
	for _, candidate := range candidates {
		if candidate.Protocol != protocol {
			continue
		}
		if candidate.Type == message.ICECandidateTypeSrflx {
			return &candidate, nil
		}
	}

	// Fall back to any candidate
	candidate := candidates[0]
	return &candidate, nil
}
