package ice

import (
	"fmt"
	"net"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/stun"
)

// PerformSTUNQuery performs a STUN query to get the public endpoint
func PerformSTUNQuery(logger common.Logger, stunServer string, localAddr net.Addr) (mappedIP net.IP, mappedPort int, err error) {
	// Perform STUN query to get our public endpoint
	switch localAddr.Network() {
	case "udp":
		var port any = localAddr.(*net.UDPAddr).Port
		mappedIP, mappedPort, err = stun.QueryServerUDP(logger, stunServer, port)
	case "tcp":
		mappedIP, mappedPort, err = stun.QueryServerTCP(logger, stunServer, localAddr.(*net.TCPAddr).Port)
	default:
		return nil, 0, fmt.Errorf("unsupported network type: %s", localAddr.Network())
	}
	return mappedIP, mappedPort, err
}
