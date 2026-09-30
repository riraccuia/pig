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

package controller

import (
	"context"
	"fmt"
	"runtime"
	"sync"

	"github.com/riraccuia/pig/pkg/adapter"
	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/demux"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/route"
	"github.com/riraccuia/pig/pkg/script"
)

type Controller struct {
	sync.WaitGroup
	cfg            *config.Config
	logger         common.Logger
	routeManager   route.Manager
	scriptExecutor *script.Executor
	clientAdapter  common.TunnelAdapter
	demux          *demux.Demux
	routeRequests  chan routeRequest
	tunnels        *sync.Map
	adapters       *sync.Map
	bufferPool     common.BufferPool
}

func New() *Controller {
	return &Controller{
		tunnels:    &sync.Map{},
		adapters:   &sync.Map{},
		bufferPool: common.DefaultBufferPool,
	}
}

func (c *Controller) Start(ctx context.Context) {
	if c.cfg == nil {
		c.logger.Fatal("no config loaded")
	}
	c.ManageRoutes(ctx)
	c.StartClient(ctx)
	c.StartServer(ctx)
}

func (c *Controller) WithLogger(logger common.Logger) *Controller {
	c.logger = logger
	return c
}

func (c *Controller) WithConfig(cfg *config.Config) *Controller {
	c.cfg = cfg
	if c.logger != nil {
		return c
	}
	c.setupLogger()
	return c
}

func (c *Controller) GetConfig() *config.Config {
	return c.cfg
}

func (c *Controller) GetLogger() common.Logger {
	return c.logger
}

func (c *Controller) LoadConfigFromFile(configPath string) error {
	cfg, err := config.LoadConfigFromFile(configPath)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}
	c.cfg = cfg
	return c.setupLogger()
}

func (c *Controller) LoadConfigFromBytes(data []byte, decodeAs string) error {
	cfg, err := config.LoadConfigFromBytes(data, decodeAs)
	if err != nil {
		return fmt.Errorf("failed to load config from bytes: %v", err)
	}
	c.cfg = cfg
	return c.setupLogger()
}

func (c *Controller) setupLogger() error {
	if c.cfg == nil {
		return fmt.Errorf("config is not loaded")
	}
	if c.logger != nil {
		return fmt.Errorf("logger is already set")
	}
	var (
		logger common.Logger
		err    error
	)
	switch c.cfg.LogConfig.File {
	case "":
		logger = log.NewLogger()
		logger.SetLevel(c.cfg.LogConfig.Level)
	default:
		logger, err = log.NewFileLogger(c.cfg.LogConfig.File, c.cfg.LogConfig.RotateSize)
		if err != nil {
			return fmt.Errorf("failed to create file logger: %v", err)
		}
		logger.SetLevel(c.cfg.LogConfig.Level)
	}
	c.logger = logger
	return nil
}

func (c *Controller) createAdapter(cfg *config.AdapterConfig, multiQueue bool) (common.TunnelAdapter, error) {
	adapterCfg := adapter.AdapterConfig{
		Address:    cfg.TunnelAddress,
		MTU:        cfg.MTU,
		MultiQueue: multiQueue && runtime.GOOS == "linux",
	}
	a, err := adapter.NewAdapter(adapterCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create adapter: %w", err)
	}
	return a, nil
}

func tunnelsByDirection(cfg *config.Config, direction config.TunnelDirection) []*config.TunnelConfig {
	tunnels := make([]*config.TunnelConfig, 0, len(cfg.Tunnels))
	for i := range cfg.Tunnels {
		if cfg.Tunnels[i].Direction == direction {
			tunnels = append(tunnels, &cfg.Tunnels[i])
		}
	}
	return tunnels
}
