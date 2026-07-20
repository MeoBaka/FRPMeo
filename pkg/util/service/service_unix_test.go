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
	"strings"
	"testing"
)

func TestUnitFile(t *testing.T) {
	unit := unitFile(Config{
		Name:        "frpc",
		DisplayName: "frp client",
		Description: "frp client",
		Exec:        "/opt/frp/frpc",
		Args:        []string{"-c", "/etc/frp/frpc.toml"},
		WorkingDir:  "/opt/frp",
	})

	for _, want := range []string{
		"ExecStart=/opt/frp/frpc -c /etc/frp/frpc.toml",
		"WorkingDirectory=/opt/frp",
		"WantedBy=multi-user.target",
		"After=network-online.target",
	} {
		if !strings.Contains(unit, want) {
			t.Errorf("unit is missing %q:\n%s", want, unit)
		}
	}

	// Restart=always is what makes an in-process restart work at all: frp
	// exits and systemd brings it back. Without it, "restart after update"
	// would leave frp down.
	if !strings.Contains(unit, "Restart=always") {
		t.Errorf("unit must restart frp, or RestartSelf leaves it stopped:\n%s", unit)
	}
	// And without lifting the burst limit, a few quick restarts make systemd
	// give up entirely.
	if !strings.Contains(unit, "StartLimitIntervalSec=0") {
		t.Errorf("unit must not let systemd give up after a few restarts:\n%s", unit)
	}
}

func TestUnitFileWithoutArgs(t *testing.T) {
	unit := unitFile(Config{Name: "frps", Description: "frp server", Exec: "/opt/frp/frps"})
	if !strings.Contains(unit, "ExecStart=/opt/frp/frps\n") {
		t.Errorf("ExecStart should have no trailing args:\n%s", unit)
	}
}
