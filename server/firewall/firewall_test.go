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

package firewall

import (
	"path/filepath"
	"testing"
)

// newTestFirewall is a firewall on a throwaway state file, with nothing turned
// on - which is what a fresh install gets.
func newTestFirewall(t *testing.T) *Firewall {
	t.Helper()
	f, err := New(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatalf("new firewall: %v", err)
	}
	return f
}

// Nothing configured means nothing refused. This layer sits in front of every
// connection frps accepts, so a default install must not lose one.
func TestEverythingIsAllowedByDefault(t *testing.T) {
	f := newTestFirewall(t)

	for range 100 {
		if v := f.AdmitTCP("1.2.3.4:1000"); !v.Allowed {
			t.Fatalf("proxy connection refused with nothing configured: %s", v.Reason)
		}
		if v := f.AdmitControl("1.2.3.4:1000"); !v.Allowed {
			t.Fatalf("control connection refused with nothing configured: %s", v.Reason)
		}
		if v := f.AdmitWeb("1.2.3.4:1000"); !v.Allowed {
			t.Fatalf("dashboard connection refused with nothing configured: %s", v.Reason)
		}
		if v := f.AdmitSSH("1.2.3.4:1000"); !v.Allowed {
			t.Fatalf("ssh connection refused with nothing configured: %s", v.Reason)
		}
		if !f.AdmitUDP("1.2.3.4:1000", 9999) {
			t.Fatal("udp packet dropped with nothing configured")
		}
	}
}

// Settings have to survive a restart: they are edited from the dashboard, and
// one that quietly reverted on the next restart would leave an operator sure
// the layer was on when it was not.
func TestConfigSurvivesReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fw.json")

	f, err := New(path)
	if err != nil {
		t.Fatalf("new firewall: %v", err)
	}
	want := Config{
		AntiAttacker: AntiAttackerConfig{
			Enabled:      true,
			GraceSeconds: 42,
			TCP:          RateProfile{Enabled: true, WindowMs: 5000, MaxPerWindow: 7},
			Control:      ControlProfile{Protect: true},
		},
	}
	if err := f.SetConfig(want); err != nil {
		t.Fatalf("set config: %v", err)
	}

	reloaded, err := New(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := reloaded.Snapshot()

	if !got.AntiAttacker.Enabled {
		t.Error("the anti-bot switch did not survive a reload")
	}
	if got.AntiAttacker.GraceSeconds != 42 {
		t.Errorf("graceSeconds = %d, want 42", got.AntiAttacker.GraceSeconds)
	}
	if got.AntiAttacker.TCP.MaxPerWindow != 7 {
		t.Errorf("tcp.maxPerWindow = %d, want 7", got.AntiAttacker.TCP.MaxPerWindow)
	}
	if !got.AntiAttacker.Control.Protect {
		t.Error("control.protect did not survive a reload")
	}
}

// A source with no port, or one that is not an address at all, must not become
// a key that collides with somebody else's.
func TestParseAddrRejectsNonsense(t *testing.T) {
	for _, s := range []string{"", "not-an-address", "1.2.3.4:notaport:extra"} {
		if a := parseAddr(s); a.IsValid() {
			t.Errorf("parseAddr(%q) = %v, want invalid", s, a)
		}
	}
	// An IPv4 client on a dual-stack listener arrives mapped; one peer has to
	// stay one key however it arrived.
	if got := parseAddr("[::ffff:203.0.113.45]:5555").String(); got != "203.0.113.45" {
		t.Errorf("mapped source key = %q, want 203.0.113.45", got)
	}
}
