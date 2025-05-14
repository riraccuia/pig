package punch

import (
	"context"
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/common"
)

// PunchUDP performs UDP hole punching from the specified source port to the target address.
// This creates a temporary opening in the NAT/firewall to allow direct UDP communication.
// A source port is required to be provided, either as an int or a *net.UDPConn. Use 0 for a random port.
func PunchUDP(ctx context.Context, logger common.Logger, connOrSourcePort any, targetAddr string) (sPort int, err error) {
	conn, ok := connOrSourcePort.(*net.UDPConn)
	if !ok {
		sourcePort, ok := connOrSourcePort.(int)
		if !ok {
			return 0, fmt.Errorf("invalid source port: %v", connOrSourcePort)
		}
		conn, err = net.ListenUDP("udp4", &net.UDPAddr{
			IP:   net.IPv4zero, // Listen on all interfaces
			Port: sourcePort,
		})
		if err != nil {
			return 0, fmt.Errorf("failed to create UDP socket on port %d: %w", sourcePort, err)
		}
		defer conn.Close()
	}

	// Resolve target address
	targetUDPAddr, err := net.ResolveUDPAddr("udp", targetAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to resolve target address %s: %w", targetAddr, err)
	}

	// Get the actual local address we're using (especially important if sourcePort was 0)
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	sPort = localAddr.Port

	// Perform the hole punch by sending a byte to the target
	punchData := []byte{0x01}

	// Send the punch packet
	logger.Debugf("Sending UDP punch packet to %s", targetUDPAddr.String())

	_, err = conn.WriteToUDP(punchData, targetUDPAddr)
	if err != nil {
		return 0, fmt.Errorf("failed to send punch packet: %w", err)
	}

	logger.Infof("UDP hole punch complete to %s (mapped endpoint: %s:%d)",
		targetAddr, localAddr.IP.String(), sPort)

	return
}
