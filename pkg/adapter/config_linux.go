package adapter

import (
	"fmt"
	"os/exec"
)

func configureTUN(ifaceName string, config AdapterConfig) error {
	// Set IP address
	cmd := exec.Command("ip", "addr", "add", config.Address, "dev", ifaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set IP: %v", err)
	}

	// Set MTU
	cmd = exec.Command("ip", "link", "set", "mtu", fmt.Sprint(config.MTU), "dev", ifaceName)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to set MTU: %v", err)
	}

	// Bring interface up
	cmd = exec.Command("ip", "link", "set", "dev", ifaceName, "up")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to bring interface up: %v", err)
	}

	return nil
}
