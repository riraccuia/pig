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

	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/controller"
	"github.com/riraccuia/pig/pkg/log"
)

func pigFromCliFlags(mo Mode) {
	startPig(initPig(mo))
}

func pigFromConfigFileFlag() {
	startPig(initPigConfig(), nil)
}

func startPig(cfg *config.Config, logger *log.Logger) {
	//enablePprof()
	var (
		ctx  = context.Background()
		ctrl *controller.Controller
	)

	ctrl = controller.New(ctx)

	if logger != nil {
		ctrl = ctrl.WithLogger(logger)
	}

	ctrl = ctrl.WithConfig(cfg)

	ctrl.Start()
	ctrl.HandleGracefulShutdown(nil)
}
