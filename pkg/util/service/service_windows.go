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

//go:build windows

package service

import (
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const (
	// How long to wait for the SCM to report a state change before giving up.
	scmTimeout = 30 * time.Second
	scmPoll    = 300 * time.Millisecond
)

// Install registers the service and sets it to start on boot.
func Install(cfg Config) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as Administrator): %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	if s, err := m.OpenService(cfg.Name); err == nil {
		s.Close()
		return fmt.Errorf("service %q is already installed", cfg.Name)
	}

	display := cfg.DisplayName
	if display == "" {
		display = cfg.Name
	}
	s, err := m.CreateService(cfg.Name, cfg.Exec, mgr.Config{
		DisplayName:  display,
		Description:  cfg.Description,
		StartType:    mgr.StartAutomatic,
		ErrorControl: mgr.ErrorNormal,
	}, cfg.Args...)
	if err != nil {
		return fmt.Errorf("create service (run as Administrator): %w", err)
	}
	defer s.Close()

	// Restart on any unexpected exit. This is both a resilience measure and the
	// mechanism RestartSelf relies on: exiting non-zero is how a running frp
	// asks to be started again.
	if err := s.SetRecoveryActions([]mgr.RecoveryAction{
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 5 * time.Second},
		{Type: mgr.ServiceRestart, Delay: 10 * time.Second},
	}, 0); err != nil {
		// Installed but without the restart policy: say so rather than leave a
		// service that silently will not come back.
		return fmt.Errorf("service installed, but setting the restart policy failed: %w", err)
	}
	return nil
}

// Uninstall stops the service if it is running and removes it.
func Uninstall(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as Administrator): %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(name)
	if err != nil {
		return ErrNotInstalled
	}
	defer s.Close()

	if st, err := s.Query(); err == nil && st.State != svc.Stopped {
		_, _ = s.Control(svc.Stop)
		_ = waitState(s, svc.Stopped)
	}
	if err := s.Delete(); err != nil {
		return fmt.Errorf("delete service: %w", err)
	}
	return nil
}

// Start starts an installed service.
func Start(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as Administrator): %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(name)
	if err != nil {
		return ErrNotInstalled
	}
	defer s.Close()

	if st, err := s.Query(); err == nil && st.State == svc.Running {
		return nil
	}
	if err := s.Start(); err != nil {
		return fmt.Errorf("start service (run as Administrator): %w", err)
	}
	return waitState(s, svc.Running)
}

// Stop stops a running service.
func Stop(name string) error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("connect to service manager (run as Administrator): %w", err)
	}
	defer func() { _ = m.Disconnect() }()

	s, err := m.OpenService(name)
	if err != nil {
		return ErrNotInstalled
	}
	defer s.Close()

	st, err := s.Query()
	if err == nil && st.State == svc.Stopped {
		return nil
	}
	if _, err := s.Control(svc.Stop); err != nil {
		return fmt.Errorf("stop service (run as Administrator): %w", err)
	}
	return waitState(s, svc.Stopped)
}

// Restart stops and starts the service. It is meant for a caller outside the
// service; frp restarting itself uses RestartSelf.
func Restart(name string) error {
	if err := Stop(name); err != nil && err != ErrNotInstalled {
		return err
	}
	return Start(name)
}

// QueryStatus reports what the manager knows about the service.
//
// It asks for read access only. mgr.Connect requests full control, which an
// ordinary user does not have - reporting "Access is denied" for a question as
// harmless as "is it running?" would push people into an elevated prompt for
// no reason.
func QueryStatus(name string) (Status, error) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return Status{}, fmt.Errorf("connect to service manager: %w", err)
	}
	m := &mgr.Mgr{Handle: scm}
	defer func() { _ = m.Disconnect() }()

	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return Status{}, err
	}
	h, err := windows.OpenService(scm, namePtr, windows.SERVICE_QUERY_STATUS|windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return Status{Installed: false, State: "not installed"}, nil
	}
	s := &mgr.Service{Name: name, Handle: h}
	defer s.Close()

	st, err := s.Query()
	if err != nil {
		return Status{Installed: true, State: "unknown"}, nil
	}
	return Status{
		Installed: true,
		Running:   st.State == svc.Running,
		State:     stateName(st.State),
		PID:       int(st.ProcessId),
	}, nil
}

func stateName(s svc.State) string {
	switch s {
	case svc.Stopped:
		return "stopped"
	case svc.StartPending:
		return "starting"
	case svc.StopPending:
		return "stopping"
	case svc.Running:
		return "running"
	case svc.ContinuePending:
		return "continuing"
	case svc.PausePending:
		return "pausing"
	case svc.Paused:
		return "paused"
	}
	return "unknown"
}

func waitState(s *mgr.Service, want svc.State) error {
	deadline := time.Now().Add(scmTimeout)
	for time.Now().Before(deadline) {
		st, err := s.Query()
		if err != nil {
			return err
		}
		if st.State == want {
			return nil
		}
		time.Sleep(scmPoll)
	}
	return fmt.Errorf("timed out waiting for service to become %s", stateName(want))
}

// RunningAsService reports whether this process was started by the SCM rather
// than from a console.
func RunningAsService() bool {
	is, err := svc.IsWindowsService()
	return err == nil && is
}

// RestartSelf asks the service manager to run frp again.
//
// Stopping and starting our own service from inside it does not work: the stop
// kills the process making the call, so the start never issues. Exiting with a
// non-zero status instead triggers the restart policy set at install time,
// which is what Install configures.
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

// Run hands control to the SCM, calling run in a goroutine and stop when the
// manager asks frp to shut down. It returns once the service has stopped.
//
// Started from a console there is no service controller to report to, and
// svc.Run would fail immediately - so an ordinary run just calls run().
func Run(name string, run func(), stop func()) error {
	if !RunningAsService() {
		run()
		return nil
	}
	return svc.Run(name, &handler{run: run, stop: stop})
}

type handler struct {
	run  func()
	stop func()
}

func (h *handler) Execute(_ []string, req <-chan svc.ChangeRequest, status chan<- svc.Status) (bool, uint32) {
	const accepted = svc.AcceptStop | svc.AcceptShutdown

	status <- svc.Status{State: svc.StartPending}
	done := make(chan struct{})
	go func() {
		defer close(done)
		h.run()
	}()
	status <- svc.Status{State: svc.Running, Accepts: accepted}

	for {
		select {
		case <-done:
			// frp returned on its own. Report a non-zero exit so the restart
			// policy treats it as a failure and brings it back.
			status <- svc.Status{State: svc.StopPending}
			return false, ExitCodeRestart
		case c := <-req:
			switch c.Cmd {
			case svc.Interrogate:
				status <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				status <- svc.Status{State: svc.StopPending}
				if h.stop != nil {
					h.stop()
				}
				return false, 0
			}
		}
	}
}
