package main

import (
	"fmt"
	"os"
	"path/filepath"
)

func receiveConfigFromControlPlane() ([]byte, error) {
	execPath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("failed to get executable path: %v", err)
	}

	configPath := filepath.Join(filepath.Dir(execPath), "config.json")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	return data, nil
}
