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

//go:build !windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const systemdDir = "/etc/systemd/system"

func unitPath(name string) string { return filepath.Join(systemdDir, name+".service") }

// Install writes a systemd unit and enables it for boot.
func Install(cfg Config) error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("systemctl not found: this installer supports systemd only")
	}
	path := unitPath(cfg.Name)
	if _, err := os.Stat(path); err == nil {
		return fmt.Errorf("service %q is already installed (%s)", cfg.Name, path)
	}

	if err := os.WriteFile(path, []byte(unitFile(cfg)), 0o644); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("write %s: permission denied (run with sudo)", path)
		}
		return fmt.Errorf("write %s: %w", path, err)
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	return systemctl("enable", cfg.Name)
}

// unitFile builds the unit. Restart=always is not only resilience: it is what
// lets frp restart itself after an update, by exiting and being brought back.
func unitFile(cfg Config) string {
	desc := cfg.Description
	if desc == "" {
		desc = cfg.DisplayName
	}
	cmd := cfg.Exec
	for _, a := range cfg.Args {
		cmd += " " + a
	}
	var b strings.Builder
	b.WriteString("[Unit]\n")
	fmt.Fprintf(&b, "Description=%s\n", desc)
	b.WriteString("After=network-online.target\n")
	b.WriteString("Wants=network-online.target\n\n")

	b.WriteString("[Service]\n")
	b.WriteString("Type=simple\n")
	fmt.Fprintf(&b, "ExecStart=%s\n", cmd)
	if cfg.WorkingDir != "" {
		fmt.Fprintf(&b, "WorkingDirectory=%s\n", cfg.WorkingDir)
	}
	b.WriteString("Restart=always\n")
	b.WriteString("RestartSec=5\n")
	// Without this, a restart loop faster than the default burst limit makes
	// systemd give up and leave frp down.
	b.WriteString("StartLimitIntervalSec=0\n")
	b.WriteString("LimitNOFILE=1048576\n\n")

	b.WriteString("[Install]\n")
	b.WriteString("WantedBy=multi-user.target\n")
	return b.String()
}

// Uninstall stops the service, disables it and removes the unit.
func Uninstall(name string) error {
	if _, err := os.Stat(unitPath(name)); err != nil {
		return ErrNotInstalled
	}
	_ = systemctl("stop", name)
	_ = systemctl("disable", name)
	if err := os.Remove(unitPath(name)); err != nil {
		if os.IsPermission(err) {
			return fmt.Errorf("remove %s: permission denied (run with sudo)", unitPath(name))
		}
		return err
	}
	return systemctl("daemon-reload")
}

// Start starts an installed service.
func Start(name string) error {
	if _, err := os.Stat(unitPath(name)); err != nil {
		return ErrNotInstalled
	}
	return systemctl("start", name)
}

// Stop stops a running service.
func Stop(name string) error {
	if _, err := os.Stat(unitPath(name)); err != nil {
		return ErrNotInstalled
	}
	return systemctl("stop", name)
}

// Restart restarts the service. It is meant for a caller outside the service;
// frp restarting itself uses RestartSelf.
func Restart(name string) error {
	if _, err := os.Stat(unitPath(name)); err != nil {
		return ErrNotInstalled
	}
	return systemctl("restart", name)
}

// QueryStatus reports what systemd knows about the service.
func QueryStatus(name string) (Status, error) {
	if _, err := os.Stat(unitPath(name)); err != nil {
		return Status{Installed: false, State: "not installed"}, nil
	}
	st := Status{Installed: true, State: "unknown"}

	// show exits 0 even for an unknown unit, so the values themselves are the
	// answer rather than the exit status.
	out, err := exec.Command("systemctl", "show", name,
		"--property=ActiveState", "--property=SubState", "--property=MainPID").Output()
	if err != nil {
		return st, nil
	}
	props := map[string]string{}
	for _, line := range strings.Split(string(out), "\n") {
		if k, v, ok := strings.Cut(strings.TrimSpace(line), "="); ok {
			props[k] = v
		}
	}
	st.State = props["ActiveState"]
	if sub := props["SubState"]; sub != "" && sub != st.State {
		st.State += " (" + sub + ")"
	}
	st.Running = props["ActiveState"] == "active"
	if pid, err := strconv.Atoi(props["MainPID"]); err == nil {
		st.PID = pid
	}
	return st, nil
}

// RunningAsService reports whether systemd started this process. systemd sets
// INVOCATION_ID for the processes it supervises.
func RunningAsService() bool {
	return os.Getenv("INVOCATION_ID") != ""
}

// RestartSelf asks systemd to run frp again.
//
// Calling "systemctl restart" on our own unit would have systemd kill the
// process making the call, so exiting non-zero and letting Restart=always bring
// frp back is both simpler and race-free.
func RestartSelf() error {
	if !RunningAsService() {
		return fmt.Errorf("not running as a service: install one with 'service install' to restart this way")
	}
	go func() {
		// Give the caller's HTTP response a moment to reach the client.
		time.Sleep(300 * time.Millisecond)
		os.Exit(ExitCodeRestart)
	}()
	return nil
}

// Run is the non-Windows counterpart of the SCM entry point: systemd runs frp
// as an ordinary foreground process, so this just calls it.
func Run(_ string, run func(), _ func()) error {
	run()
	return nil
}

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if strings.Contains(msg, "Access denied") || strings.Contains(msg, "permission") {
			return fmt.Errorf("systemctl %s: %s (run with sudo)", strings.Join(args, " "), msg)
		}
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "), msg)
	}
	return nil
}
