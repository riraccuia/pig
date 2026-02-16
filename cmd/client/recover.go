package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// setupPanicLogFile opens "<binary-name>.panic.log" beside the executable and
// redirects stderr to it so panic information is persisted.
func setupPanicLogFile() (*os.File, error) {
	executablePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("resolve executable path: %w", err)
	}

	logFilePath := filepath.Join(
		filepath.Dir(executablePath),
		filepath.Base(executablePath)+".panic.log",
	)

	logFile, err := os.OpenFile(logFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("open panic log file %q: %w", logFilePath, err)
	}

	os.Stderr = logFile
	return logFile, nil
}

// recoverToLogFile writes panic information to the panic log.
func recoverToLogFile() {
	recovered := recover()
	if recovered == nil {
		return
	}

	target := os.Stderr
	logFile, err := setupPanicLogFile()
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Failed to setup panic log file: %v\n", err)
	}
	defer logFile.Close()
	target = logFile

	_, _ = fmt.Fprintf(target, "[%s] panic recovered: %v\n", time.Now().Format(time.RFC3339), recovered)
}
