// Copyright 2026 Riccardo Raccuia
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/controller"
)

func pigFromCliFlags(mo Mode) {
	startPig(initPig(mo))
}

func pigFromConfigFileFlag() {
	startPig(initPigConfig(), nil)
}

func startPig(cfg *config.Config, logger common.Logger) {
	//enablePprof()
	var (
		ctx    context.Context
		cancel context.CancelFunc
		ctrl   *controller.Controller
	)

	ctx, cancel = getOSignalCtx()
	defer cancel()

	ctrl = controller.New()

	if logger != nil {
		ctrl = ctrl.WithLogger(logger)
	}

	ctrl = ctrl.WithConfig(cfg)

	if logger == nil {
		// after calling WithConfig, the logger will be set
		logger = ctrl.GetLogger()
	}

	ctrl.Start(ctx)

	<-ctx.Done()

	logger.Infof("Shutting down: %v", context.Cause(ctx))

	logger.Flush()
}

func getOSignalCtx() (context.Context, context.CancelFunc) {
	ctx, cancel := signal.NotifyContext(context.Background(),
		os.Interrupt,    // SIGINT (Ctrl+C)
		syscall.SIGTERM, // SIGTERM (termination request)
		syscall.SIGQUIT, // SIGQUIT (quit from keyboard)
	)
	return ctx, cancel
}
