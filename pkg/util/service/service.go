// Copyright 2026 The frp Authors
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

// Package service installs frp under the host's service manager - the Windows
// SCM or systemd - so it starts on boot and can be restarted after an update.
//
// Every installation is configured to restart frp if it exits unexpectedly.
// That is what makes an in-process restart possible at all: a process cannot
// relaunch itself without either leaving an orphan or racing its own shutdown,
// but it can exit and let the manager start it again. See RestartSelf.
package service

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ExitCodeRestart is the status frp exits with when it wants the service
// manager to start it again. Any non-zero code reads as an unexpected exit,
// which is exactly the condition the restart policy is configured for.
const ExitCodeRestart = 92

// ErrNotInstalled is returned when an operation names a service that is not
// installed.
var ErrNotInstalled = errors.New("service is not installed")

// Config describes the service to install.
type Config struct {
	// Name is the service name, "frpc" or "frps".
	Name string
	// DisplayName and Description are shown by the service manager.
	DisplayName string
	Description string
	// Exec is the absolute path to the frp binary.
	Exec string
	// Args are the arguments it is started with, typically -c <config>.
	Args []string
	// WorkingDir is where the process runs; relative paths in the config
	// resolve against it.
	WorkingDir string
}

// Status is what the manager reports about a service.
type Status struct {
	Installed bool
	Running   bool
	// State is the manager's own word for it, for display.
	State string
	// PID is the running process, 0 when not running or not reported.
	PID int
}

func (s Status) String() string {
	if !s.Installed {
		return "not installed"
	}
	if s.PID > 0 {
		return fmt.Sprintf("%s (pid %d)", s.State, s.PID)
	}
	return s.State
}

// NewConfig fills in the parts that are the same everywhere: the running
// binary's own path, and a working directory that keeps relative config paths
// meaning what they meant on the command line.
func NewConfig(name, displayName, description, configFile string) (Config, error) {
	exe, err := os.Executable()
	if err != nil {
		return Config{}, fmt.Errorf("locate executable: %w", err)
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}

	cfg := Config{
		Name:        name,
		DisplayName: displayName,
		Description: description,
		Exec:        exe,
		WorkingDir:  filepath.Dir(exe),
	}
	if configFile != "" {
		abs, err := filepath.Abs(configFile)
		if err != nil {
			return Config{}, fmt.Errorf("resolve config path: %w", err)
		}
		if _, err := os.Stat(abs); err != nil {
			// A service that starts and immediately fails on a missing config
			// is worse than a refusal here: the manager will retry it forever.
			return Config{}, fmt.Errorf("config file %s: %w", abs, err)
		}
		cfg.Args = []string{"-c", abs}
	}
	return cfg, nil
}
