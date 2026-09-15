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
)

// ScriptContext holds all the context information needed for script execution.
type ScriptContext struct {
	EventName    string // Name of the event
	TunnelName   string // Name of the tunnel
	AdapterName  string // Name of the tunnel adapter
	AdapterIndex int    // Index of the tunnel adapter
	RemoteAddr   string // Remote end IP address
	NatAddr      string // Client's allocated IP (server mode only)
	TunnelProto  string // Protocol used for the tunnel
}

// Executor handles the execution of scripts when tunnel connections are established or disconnected.
type Executor struct {
	Logger     common.Logger
	ScriptPath string
}

// New creates a new script executor.
func New(logger common.Logger, scriptPath string) *Executor {
	return &Executor{
		Logger:     logger,
		ScriptPath: scriptPath,
	}
}

// ExecuteStartScript executes the start script in a fire-and-forget manner.
func (e *Executor) ExecuteScript(ctx ScriptContext) {
	if e.ScriptPath == "" {
		return
	}

	e.executeScript(e.ScriptPath, ctx)
}

// executeScript executes a script with environment variables containing tunnel information.
func (e *Executor) executeScript(scriptPath string, ctx ScriptContext) {
	// Check if script exists and is executable
	scriptAbsPath, err := filepath.Abs(scriptPath)
	if err != nil {
		e.Logger.Errorf("Failed to get absolute path for script %s: %v", scriptPath, err)
		return
	}

	info, err := os.Stat(scriptAbsPath)
	if err != nil {
		e.Logger.Errorf("Script %s not found: %v", scriptAbsPath, err)
		return
	}

	if info.IsDir() {
		e.Logger.Errorf("Script path %s is a directory, not a file", scriptAbsPath)
		return
	}

	// Check if the script is executable on Unix systems
	if isUnix() {
		if info.Mode()&0111 == 0 {
			e.Logger.Errorf("Script %s is not executable, attempting to execute anyway", scriptAbsPath)
		}
	}

	// Create a context with timeout to prevent hanging scripts
	execCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create command
	cmd := exec.CommandContext(execCtx, scriptAbsPath)

	// Set environment variables
	cmd.Env = append(os.Environ(),
		EnvEventName.Name()+"="+ctx.EventName,
		EnvTunnelName.Name()+"="+ctx.TunnelName,
		EnvAdapterName.Name()+"="+ctx.AdapterName,
		EnvAdapterIndex.Name()+"="+strconv.Itoa(ctx.AdapterIndex),
		EnvRemoteAddr.Name()+"="+ctx.RemoteAddr,
		EnvNatAddr.Name()+"="+ctx.NatAddr,
		EnvTunnelProto.Name()+"="+ctx.TunnelProto,
	)

	e.Logger.Infof("Executing script %s", scriptAbsPath)
	var stdout []byte
	// Start the command without waiting for it to complete (fire-and-forget)
	if stdout, err = cmd.Output(); err != nil {
		e.Logger.Errorf("Script %s exited with error: %v", scriptAbsPath, err)
		return
	}

	e.Logger.Debugf("Script %s stdout: \n%s", scriptAbsPath, stdout)
}

// isUnix returns true if the current OS is a Unix-like system.
func isUnix() bool {
	return runtime.GOOS != "windows"
}
