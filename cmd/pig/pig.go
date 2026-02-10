package main

import (
	"context"

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/controller"
	"github.com/riraccuia/pig/pkg/log"
)

func pig(mo config.Mode) {
	var (
		ctx    = context.Background()
		logger *log.Logger
		cfg    *config.Config
		ctrl   *controller.Controller
	)

	cfg, logger = initPig(mo)

	ctrl = controller.New(ctx)
	ctrl = ctrl.WithLogger(logger).WithConfig(cfg)

	// write the configuration to a file, in json format
	/*cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		logger.Fatalf("Failed to marshal configuration: %v", err)
	}
	os.WriteFile("pig_config_exported.json", cfgJSON, 0644)*/

	switch cfg.Mode {
	case "client":
		ctrl.StartClient()
	case "server":
		ctrl.StartServer()
	default:
		logger.Fatalf("Invalid mode: %s", cfg.Mode)
	}
	ctrl.HandleGracefulShutdown(nil)
}
