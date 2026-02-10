package main

import (
	"context"
	"fmt"
	"os"

	"github.com/riraccuia/pig/pkg/controller"
)

var (
	ctrl *controller.Controller
)

func runClient(ctx context.Context, serviceMode bool) {
	configBytes, err := receiveConfigFromControlPlane()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to receive config: %v\n", err)
		return
	}

	ctrl = controller.New(ctx)

	err = ctrl.LoadConfigFromBytes(configBytes, "json")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config: %v\n", err)
		return
	}

	ctrl.StartClient()

	if !serviceMode {
		ctrl.HandleGracefulShutdown(nil)
	}
}
