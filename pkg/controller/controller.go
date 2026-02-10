package controller

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
	"github.com/riraccuia/pig/pkg/log"
	"github.com/riraccuia/pig/pkg/route"
	"github.com/riraccuia/pig/pkg/script"
)

type Controller struct {
	*sync.WaitGroup
	cfg            *config.Config
	logger         common.Logger
	ctx            context.Context
	cancel         context.CancelCauseFunc
	routeManager   *route.Manager
	scriptExecutor *script.Executor
}

type Waiter interface {
	WaitClose()
}

func New(ctx context.Context) *Controller {
	iCtx, cancel := context.WithCancelCause(ctx)
	routeManager, err := route.NewManager(iCtx)
	if err != nil {
		log.NewBlockingLogger().Fatalf("Failed to init controller's route manager: %v", err)
	}
	return &Controller{
		WaitGroup:    &sync.WaitGroup{},
		ctx:          iCtx,
		cancel:       cancel,
		routeManager: routeManager,
	}
}

func (c *Controller) WithLogger(logger common.Logger) *Controller {
	c.logger = logger
	return c
}

func (c *Controller) WithConfig(cfg *config.Config) *Controller {
	c.cfg = cfg
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
		logger, err = log.NewFileLogger(c.cfg.LogConfig.File, c.cfg.LogConfig.RotateSize.(int64))
		if err != nil {
			return fmt.Errorf("failed to create file logger: %v", err)
		}
		logger.SetLevel(c.cfg.LogConfig.Level)
	}
	c.logger = logger
	return nil
}

func (c *Controller) StartCallback(callback func(ctx context.Context)) {
	c.Add(1)
	go func() {
		defer c.Done()
		callback(c.ctx)
	}()
}

func (c *Controller) WaitClose() {
	c.WaitGroup.Wait()
}

// HandleGracefulShutdown will wait (block) for an OS signal to be received and then gracefully shutdown the controller.
func (c *Controller) HandleGracefulShutdown(waiter Waiter) {
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
	c.logger.Infof("Received signal: %v, initiating graceful shutdown...", sig)
	// Cancel the context to signal all goroutines to stop
	c.cancel(fmt.Errorf("received signal: %v", sig))
	// Close the closer if it is not nil
	if waiter != nil {
		waiter.WaitClose()
	}
	// Wait for all goroutines to finish
	c.Wait() // this will wait for all goroutines to finish
	c.logger.Info("Graceful shutdown completed")
	// used to flush the log buffer
	time.Sleep(time.Millisecond * 100)
}
