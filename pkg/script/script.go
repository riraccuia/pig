package script

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/riraccuia/pig/pkg/common"
	"github.com/riraccuia/pig/pkg/config"
)

// ScriptContext holds all the context information needed for script execution
type ScriptContext struct {
	TunnelName  string // Name of the tunnel adapter
	TunnelIndex int    // Index of the tunnel adapter
	RemoteAddr  string // Remote end IP address
	NatAddr     string // Client's allocated IP (server mode only)
	TunnelProto string // Protocol used for the tunnel
}

// Executor handles the execution of scripts when tunnel connections are established or disconnected
type Executor struct {
	logger common.Logger
	config *config.Config
}

// New creates a new script executor
func New(logger common.Logger, cfg *config.Config) *Executor {
	return &Executor{
		logger: logger,
		config: cfg,
	}
}

// ExecuteStartScript executes the start script in a fire-and-forget manner
func (e *Executor) ExecuteStartScript(ctx ScriptContext) {
	if e.config.StartScript == "" {
		return
	}

	e.executeScript(e.config.StartScript, ctx)
}

// ExecuteStopScript executes the stop script in a fire-and-forget manner
func (e *Executor) ExecuteStopScript(ctx ScriptContext) {
	if e.config.StopScript == "" {
		return
	}

	e.executeScript(e.config.StopScript, ctx)
}

// executeScript executes a script with environment variables containing tunnel information
func (e *Executor) executeScript(scriptPath string, ctx ScriptContext) {
	// Check if script exists and is executable
	scriptAbsPath, err := filepath.Abs(scriptPath)
	if err != nil {
		e.logger.Errorf("Failed to get absolute path for script %s: %v", scriptPath, err)
		return
	}

	info, err := os.Stat(scriptAbsPath)
	if err != nil {
		e.logger.Errorf("Script %s not found: %v", scriptAbsPath, err)
		return
	}

	if info.IsDir() {
		e.logger.Errorf("Script path %s is a directory, not a file", scriptAbsPath)
		return
	}

	// Check if the script is executable on Unix systems
	if isUnix() {
		if info.Mode()&0111 == 0 {
			e.logger.Errorf("Script %s is not executable, attempting to execute anyway", scriptAbsPath)
		}
	}

	// Create a context with timeout to prevent hanging scripts
	execCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create command
	cmd := exec.CommandContext(execCtx, scriptAbsPath)

	// Set environment variables
	cmd.Env = append(os.Environ(),
		"PIG_TUN_NAME="+ctx.TunnelName,
		"PIG_TUN_INDEX="+strconv.Itoa(ctx.TunnelIndex),
		"PIG_REMOTE_ADDR="+ctx.RemoteAddr,
		"PIG_NAT_ADDR="+ctx.NatAddr,
		"PIG_TUNNEL_PROTO="+ctx.TunnelProto,
	)

	e.logger.Infof("Executing script %s", scriptAbsPath)
	var stdout []byte
	// Start the command without waiting for it to complete (fire-and-forget)
	if stdout, err = cmd.Output(); err != nil {
		e.logger.Errorf("Script %s exited with error: %v", scriptAbsPath, err)
		return
	}

	e.logger.Debugf("Script %s stdout: \n%s", scriptAbsPath, stdout)
}

// isUnix returns true if the current OS is a Unix-like system
func isUnix() bool {
	return runtime.GOOS != "windows"
}
