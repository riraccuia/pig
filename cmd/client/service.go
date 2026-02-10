package main

import (
	"context"
	"fmt"
	"os"

	"github.com/riraccuia/pig/pkg/service"
)

var clientCancel context.CancelFunc

func runService() {
	handler, err := service.New("PigClient", onStart, onStop)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create service handler: %v\n", err)
		os.Exit(1)
	}
	err = handler.Run()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Service failed: %v\n", err)
		os.Exit(1)
	}
}

func onStart() error {
	ctx, cancel := context.WithCancel(context.Background())
	clientCancel = cancel
	go runClient(ctx, true)
	return nil
}

func onStop() error {
	if clientCancel != nil {
		clientCancel()
	}
	if ctrl != nil {
		ctrl.WaitClose()
	}
	return nil
}
