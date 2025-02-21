//go:build windows
// +build windows

package adapter

import (
	"fmt"
	"os/exec"
)

func configureWinTun(ifaceName string, config AdapterConfig) error {
	// Set IP address
	cmd := exec.Command("netsh", "interface", "ip", "set", "address",
		fmt.Sprintf("name=\"%s\"", ifaceName),
		"static",
		config.Address)
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
