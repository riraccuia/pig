//go:build linux
// +build linux

package icmp

import (
	"fmt"
	"os"
)

func initSystem() error {
	if err := os.WriteFile("/proc/sys/net/ipv4/icmp_echo_ignore_all", []byte("1\n"), 0644); err != nil {
		return fmt.Errorf("failed to set sysctl: %w", err)
	}
	return nil
}
