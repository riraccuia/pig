package ice

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/ice/signaling"
	"github.com/riraccuia/pig/pkg/network"
	"github.com/riraccuia/pig/pkg/stun"
	"github.com/riraccuia/pig/pkg/transport"
	"github.com/riraccuia/pig/pkg/transport/icmp"
)

var ErrConnectICMP = fmt.Errorf("call ConnectICMP instead")

// ConnectPath represents a network path for a connection
// it is used to store information that will be exchanged
// between the client and the server using the ICE protocol
type ConnectPath struct {
	ICEID       string
	Family      int // AF_INET or AF_INET6
	LocalNet    *net.IPNet
	LocalAddr   net.Addr
	RemoteAddr  net.Addr
	Protocol    transport.ICEProtocolDefinition
	BindAgent   *stun.IceBindingAgent
	Conn        net.Conn
	ScheduledAt time.Time // the time at which the connection should be established
}

// String returns a string representation of the ConnectPath
func (cp ConnectPath) String() string {
	return fmt.Sprintf("id=%s proto=%s local=%s remote=%s", cp.ICEID, cp.Protocol.Protocol, cp.LocalAddr.String(), cp.RemoteAddr.String())
}

// Connect establishes a layer 4 (e.g. UDP, TCP, ICMP) connection to the remote address
// it will use the local address and port specified in the ConnectPath.
// It also sets the obtained connection to the embedded ICE binding agent.
func (cp *ConnectPath) Connect() (co net.Conn, err error) {
	switch cp.Protocol.Network {
	case "udp":
		var _co *net.UDPConn
		_co, err = network.DialUDP("udp", cp.LocalAddr.(*net.UDPAddr), cp.RemoteAddr.(*net.UDPAddr))
		//co = conn.NewUDPPacketConn(_co)
		co = _co
	case "tcp":
		co, err = network.DialTCP("tcp", cp.LocalAddr.(*net.TCPAddr), cp.RemoteAddr.(*net.TCPAddr))
	case "icmp":
		return nil, ErrConnectICMP
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

// ConnectICMP is the same as Connect but for ICMP.
func (cp *ConnectPath) ConnectICMP(ctx context.Context, logger common.Logger, bindAdapter string, isServer bool) (co net.Conn, err error) {
	if cp.Protocol.Network != "icmp" {
		return nil, fmt.Errorf("protocol is not icmp: %s", cp.Protocol.Network)
	}
	remoteAddr := cp.RemoteAddr.(*net.IPAddr)
	// convert the ice id to an int16
	icmpID := binary.BigEndian.Uint16([]byte(cp.ICEID))
	co, err = icmp.Dial(ctx, logger, bindAdapter, remoteAddr.IP.String(), icmpID, isServer)
	if err != nil {
		return nil, err
	}
	cp.Conn = co
	cp.BindAgent.Conn = co
	return
}

// ICESetup sends a binding request to the remote peer and waits for the first binding response.
// Then it starts receiving binding requests on the connection out of band.
func (cp *ConnectPath) ICESetup() error {
	if cp.BindAgent == nil || cp.BindAgent.Conn == nil {
		return fmt.Errorf("the bind agent is not ready, call Connect first")
	}
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

func getPathForProto(tr transport.ICEProtocolDefinition, localNet *net.IPNet, localIp, remoteIp net.IP, listenPort uint16, opts *signaling.Options) (cp *ConnectPath) {
	var (
		localAddr  net.Addr
		remoteAddr net.Addr
	)
	if localIp != nil {
		localAddr = AddressFrom(tr.Network, localIp, int(listenPort))
	}
	if remoteIp != nil {
		remoteAddr = AddressFrom(tr.Network, remoteIp, int(listenPort))
	}
	cp = &ConnectPath{
		Family:     getFamilyForIP(localIp),
		LocalNet:   localNet,
		LocalAddr:  localAddr,
		RemoteAddr: remoteAddr,
		Protocol:   tr,
		BindAgent:  stun.NewIceBindingAgent(opts.Logger, nil),
	}
	return cp
}

func getFamilyForIP(ip net.IP) int {
	if ip.To4() != nil {
		return 0x2 // AF_INET
	}
	return 0xa // AF_INET6
}
