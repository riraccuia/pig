//go:build windows
// +build windows

package adapter

import (
	"fmt"
	"net"
	"os/exec"
)

func configureWinTun(ifaceName string, config AdapterConfig) error {
	ip, network, err := net.ParseCIDR(config.Address)
	if err != nil {
		return fmt.Errorf("failed to parse IP: %v", err)
	}
	// Set IP address
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=\"%s\"", ifaceName),
		"static",
		ip.String(),
		network.Mask.String())
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP: %v", err)
	}

	// Set MTU
	cmd = exec.Command("netsh", "interface", "ipv4", "set", "subinterface",
		fmt.Sprintf("\"%s\"", ifaceName),
		fmt.Sprintf("mtu=%d", config.MTU))
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	return nil
}
