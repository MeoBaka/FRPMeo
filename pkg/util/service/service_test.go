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

package service

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The config path has to be absolute in the unit: a service starts from a
// working directory the user never sees, so a relative -c would resolve
// somewhere else than it did on the command line.
func TestNewConfigMakesConfigPathAbsolute(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "frpc.toml")
	if err := os.WriteFile(cfgFile, []byte("serverAddr = \"127.0.0.1\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	wd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(wd) })
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}

	cfg, err := NewConfig("frpc", "frp client", "desc", "frpc.toml")
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if len(cfg.Args) != 2 || cfg.Args[0] != "-c" {
		t.Fatalf("args should be -c <path>, got %v", cfg.Args)
	}
	if !filepath.IsAbs(cfg.Args[1]) {
		t.Fatalf("config path must be absolute, got %q", cfg.Args[1])
	}
	if cfg.Exec == "" || !filepath.IsAbs(cfg.Exec) {
		t.Fatalf("exec path must be absolute, got %q", cfg.Exec)
	}
}

// Installing a service whose config is missing would leave the manager
// restarting a process that cannot start, forever.
func TestNewConfigRejectsMissingConfig(t *testing.T) {
	_, err := NewConfig("frpc", "frp client", "desc", filepath.Join(t.TempDir(), "nope.toml"))
	if err == nil {
		t.Fatal("a missing config file must be refused at install time")
	}
	if !strings.Contains(err.Error(), "nope.toml") {
		t.Fatalf("the error should name the file, got %v", err)
	}
}

func TestNewConfigWithoutConfigFile(t *testing.T) {
	cfg, err := NewConfig("frps", "frp server", "desc", "")
	if err != nil {
		t.Fatalf("NewConfig: %v", err)
	}
	if len(cfg.Args) != 0 {
		t.Fatalf("no config file means no -c, got %v", cfg.Args)
	}
}

func TestStatusString(t *testing.T) {
	if got := (Status{}).String(); got != "not installed" {
		t.Fatalf("got %q", got)
	}
	if got := (Status{Installed: true, State: "running", PID: 42}).String(); got != "running (pid 42)" {
		t.Fatalf("got %q", got)
	}
	if got := (Status{Installed: true, State: "stopped"}).String(); got != "stopped" {
		t.Fatalf("got %q", got)
	}
}
