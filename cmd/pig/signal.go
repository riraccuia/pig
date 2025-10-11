package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/riraccuia/pig/pkg/common"
)

// handleGracefulShutdown implements idiomatic Go signal handling
func handleGracefulShutdown(ctx context.Context, logger common.Logger, cancel context.CancelFunc, closer io.Closer) {
	// Create signal channel with buffer size 1 to avoid blocking
	sigChan := make(chan os.Signal, 1)

	// Register for essential signals
	signal.Notify(sigChan,
		os.Interrupt,    // SIGINT (Ctrl+C)
		syscall.SIGTERM, // SIGTERM (termination request)
		syscall.SIGQUIT, // SIGQUIT (quit from keyboard)
	)

	// Block until we receive a signal
	sig := <-sigChan
	logger.Infof("Received signal: %v, initiating graceful shutdown...", sig)

	// Cancel the context to signal all goroutines to stop
	cancel()

	// Create a timeout context for cleanup operations
	var shutdownCancel context.CancelCauseFunc
	shutdownCtx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	shutdownCtx, shutdownCancel = context.WithCancelCause(shutdownCtx)
	defer shutdownCancel(nil)

	// Perform graceful shutdown in a goroutine
	shutdownComplete := make(chan struct{})
	go func() {
		defer close(shutdownComplete)

		if closer == nil {
			return
		}

		logger.Info("Closing pig...")
		if err := closer.Close(); err != nil {
			shutdownCancel(fmt.Errorf("error closing server: %v", err))
			return
		}
	}()

	// Wait for shutdown to complete or timeout
	select {
	case <-shutdownComplete:
		logger.Info("Graceful shutdown completed")
	case <-shutdownCtx.Done():
		err := shutdownCtx.Err()
		if err != nil {
			logger.Error("Shutdown error: %w", err)
			return
		}
		logger.Error("Shutdown timeout exceeded, forcing exit")
	}
	// used to flush the log buffer
	time.Sleep(time.Millisecond * 100)
}
