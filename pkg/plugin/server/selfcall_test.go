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

package server

import (
	"testing"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func pluginOptionsNamed(name string) v1.HTTPPluginOptions {
	return v1.HTTPPluginOptions{Name: name, Ops: []string{OpNewUserConn}}
}

// Fixed sets, so the result does not depend on the interfaces of the machine
// running the test.
func newSelfCallManager(selfPort int) *Manager {
	m := NewManager()
	m.localIPs = map[string]bool{"127.0.0.1": true, "10.1.2.3": true}
	m.selfPorts = map[int]bool{selfPort: true}
	return m
}

func TestIsSelfCall(t *testing.T) {
	m := newSelfCallManager(7002)

	cases := []struct {
		name       string
		remoteAddr string
		port       int
		want       bool
	}{
		// frps calling the plugin published at its own :7002 - the loop
		{"our address, plugin port", "10.1.2.3:50315", 7002, true},
		{"loopback, plugin port", "127.0.0.1:50316", 7002, true},

		// A real visitor of that same port: still hooked, the plugin is there
		// to rule on exactly this.
		{"remote visitor, plugin port", "203.0.113.9:50317", 7002, false},

		// Our own traffic to anything else is ordinary user traffic.
		{"our address, other port", "10.1.2.3:50318", 6000, false},
		{"loopback, other port", "127.0.0.1:50319", 6000, false},

		{"remote visitor, other port", "203.0.113.9:50320", 6000, false},
	}
	for _, c := range cases {
		if got := m.IsSelfCall(c.remoteAddr, c.port); got != c.want {
			t.Errorf("%s: IsSelfCall(%q, %d) = %v, want %v", c.name, c.remoteAddr, c.port, got, c.want)
		}
	}
}

// With no plugin behind one of our own proxies, nothing is ever skipped.
func TestIsSelfCallNoSelfPlugin(t *testing.T) {
	m := NewManager()
	m.localIPs = map[string]bool{"127.0.0.1": true}

	for _, port := range []int{80, 6000, 7002} {
		if m.IsSelfCall("127.0.0.1:1", port) {
			t.Errorf("port %d: nothing should be skipped when no plugin is self-hosted", port)
		}
	}
}

func TestRegisterMarksSelfHostedPlugin(t *testing.T) {
	m := NewManager()
	m.localIPs = map[string]bool{"127.0.0.1": true}

	// 127.0.0.1 is ours -> the plugin is behind one of our own proxies.
	m.Register(&httpPlugin{options: pluginOptionsNamed("local"), url: "http://127.0.0.1:7002/handler"})
	if !m.selfPorts[7002] {
		t.Fatal("a plugin on our own address must be noted, or its hook will call itself")
	}

	// A plugin somewhere else must not be mistaken for one of ours, or every
	// port sharing its number would quietly lose the hook.
	m2 := NewManager()
	m2.localIPs = map[string]bool{"127.0.0.1": true}
	m2.Register(&httpPlugin{options: pluginOptionsNamed("remote"), url: "http://203.0.113.9:7002/handler"})
	if len(m2.selfPorts) != 0 {
		t.Fatalf("a remote plugin is not self-hosted, got selfPorts %v", m2.selfPorts)
	}
}
