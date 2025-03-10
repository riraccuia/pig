//go:build darwin
// +build darwin

package adapter

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"
)

func TestTUNAdapterCreation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping test in short mode")
	}

	// Create a new adapter with test configuration
	config := AdapterConfig{
		Address: "10.0.0.1/28",
		MTU:     1300,
	}

	adapter, err := newAdapter(config)
	if err != nil {
		t.Fatalf("Failed to create TUN adapter: %v", err)
	}
	defer adapter.Close()

	// Get the adapter name
	adapterName := adapter.Name()
	t.Log("Adapter name:", adapterName)
	if !strings.HasPrefix(adapterName, "utun") {
		t.Errorf("Expected adapter name to start with 'utun', got %s", adapterName)
	}

	// Verify adapter exists using ifconfig
	cmd := exec.Command("ifconfig", adapterName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("Failed to run ifconfig: %v", err)
	}

	outputStr := string(output)

	// Verify adapter is present in system
	if !strings.Contains(outputStr, adapterName) {
		t.Errorf("Adapter %s not found in ifconfig output", adapterName)
	}

	// Verify adapter has correct IP
	if !strings.Contains(outputStr, "10.0.0.1") {
		t.Errorf("Expected IP 10.0.0.1 not found in adapter configuration")
	}

	// Verify adapter is UP
	if !strings.Contains(outputStr, "UP") {
		t.Errorf("Adapter is not in UP state")
	}

	// Verify MTU
	if !strings.Contains(outputStr, fmt.Sprintf("mtu %d", config.MTU)) {
		t.Errorf("Expected MTU %d not found in adapter configuration", config.MTU)
	}
}
