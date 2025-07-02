package ice

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"slices"

	"github.com/riraccuia/pig/pkg/ice/conn"
	"github.com/riraccuia/pig/pkg/ice/message"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/stun"
	"github.com/riraccuia/pig/pkg/transport"
)

type ConnectPath struct {
	ICEID      string
	LocalNet   *net.IPNet
	LocalAddr  net.Addr
	RemoteAddr net.Addr
	Protocol   transport.ICEProtocolDefinition
	BindAgent  *stun.IceBindingAgent
	Conn       net.Conn
}

func (cp *ConnectPath) Connect() (co net.Conn, err error) {
	switch cp.Protocol.Network {
	case "udp":
		var _co *net.UDPConn
		_co, err = conn.DialUDP("udp4", cp.LocalAddr.(*net.UDPAddr), cp.RemoteAddr.(*net.UDPAddr))
		//co = conn.NewUDPPacketConn(_co)
		co = _co
	case "tcp":
		co, err = conn.DialTCP("tcp4", cp.LocalAddr.(*net.TCPAddr), cp.RemoteAddr.(*net.TCPAddr))
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", cp.Protocol.Network)
	}
	if err != nil {
		return nil, err
	}
	if co == nil {
		return nil, fmt.Errorf("failed to connect unknown error")
	}
	cp.Conn = co
	cp.BindAgent.Conn = co
	return
}

func (cp *ConnectPath) ICESetup() error {
	// wait for the first binding response
	_, err := cp.BindAgent.SendBindingRequest(true)
	if err != nil {
		return fmt.Errorf("failed to send binding request: %w", err)
	}
	// let the binding agent handle requests out of band
	// this call will not block
	cp.BindAgent.Receive()
	return nil
}

func (cp *ConnectPath) CloseConn() error {
	if cp.Conn == nil {
		return nil
	}
	return cp.Conn.Close()
}

func (cp ConnectPath) String() string {
	return fmt.Sprintf("proto=%s id=%s local=%s remote=%s", cp.Protocol.Protocol, cp.ICEID, cp.LocalAddr.String(), cp.RemoteAddr.String())
}

func GetConnectPaths(ctx context.Context, opts *signaling.Options, addr string, pigProtos []transport.ICEProtocolDefinition) (cp []*ConnectPath, err error) {
	localNets, localIps, err := getLocalNetworks()
	if err != nil {
		return nil, err
	}

	var offerCandidates []message.ICECandidate

	for _, tr := range pigProtos {
		// local candidates
		for i, localIp := range localIps {
			bindAgent := stun.NewIceBindingAgent(opts.Logger, nil)
			srcPort := rand.Intn(65535-1024) + 1024
			localAddr := AddressFrom(tr.Network, localIp, srcPort)
			cp = append(cp, &ConnectPath{
				LocalNet:  localNets[i],
				LocalAddr: localAddr,
				Protocol:  tr,
				BindAgent: bindAgent,
			})
			candidate := CandidateFrom(tr.Network, tr.ComponentID, localIp, srcPort)
			offerCandidates = append(offerCandidates, candidate)
			bindAgent.Ice = &stun.IceAttributes{
				Priority:       candidate.Priority,
				IceControlling: 0x12345678,
			}
		}
		// reflexive candidate
		localAddr := AddressFrom(tr.Network, net.IPv4zero, 0)
		// Get mapped endpoint
		mappedIP, mappedPort, err := PerformSTUNQuery(opts.Logger, opts.STUNServer, localAddr)
		if err != nil {
			return nil, fmt.Errorf("STUN query failed: %w", err)
		}
		bindAgent := stun.NewIceBindingAgent(opts.Logger, nil)
		cp = append(cp, &ConnectPath{
			LocalAddr: localAddr,
			Protocol:  tr,
			BindAgent: bindAgent,
		})
		candidate := CandidateFrom(tr.Network, tr.ComponentID, mappedIP, mappedPort)
		offerCandidates = append(offerCandidates, candidate)
		bindAgent.Ice = &stun.IceAttributes{
			Priority:       candidate.Priority,
			IceControlling: 0x12345678,
		}
	}

	var (
		offer, answer *message.ICEMessage
	)

	offer, err = message.GenerateICEOffer(offerCandidates)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ICE offer: %w", err)
	}

	answer, err = signaling.GatherICECandidates(ctx, opts, addr, offer)
	if err != nil {
		return
	}

	opts.Logger.Debugf("answerCandidates: %v", answer.Candidates)

	iceAuth := &stun.StunAuthConfig{
		Username:     offer.Credentials.Username,
		Password:     offer.Credentials.Password,
		PeerUsername: answer.Credentials.Username,
		PeerPassword: answer.Credentials.Password,
	}

	for _, candidate := range answer.Candidates {
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
			connect.ICEID = answer.SessionID
			connect.RemoteAddr = AddressFrom(connect.Protocol.Network, targetIP, candidate.Port)
			connect.BindAgent.Auth = iceAuth
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
