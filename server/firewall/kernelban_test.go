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
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// recordingSink stands in for the host firewall so the tests can read what
// would have been programmed into it.
type recordingSink struct {
	mu      sync.Mutex
	banned  []netip.Addr
	ttls    []time.Duration
	drained int
}

func (s *recordingSink) ban(ip netip.Addr, ttl time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.banned = append(s.banned, ip)
	s.ttls = append(s.ttls, ttl)
}

func (s *recordingSink) drain() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.drained++
}

func (s *recordingSink) name() string { return "recording" }

func (s *recordingSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.banned)
}

// banFirewall arms a control limit tight enough to ban on the second overflow,
// with the attack detector off so the ban is not withheld for being calm.
func banFirewall(t *testing.T) (*Firewall, *recordingSink) {
	t.Helper()

	f, err := New(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatalf("new firewall: %v", err)
	}
	if err := f.SetConfig(Config{
		AntiAttacker: AntiAttackerConfig{
			Enabled: true,
			Control: ControlProfile{Protect: true, RateProfile: RateProfile{
				WindowMs: 60000, MaxPerWindow: 1, BanViolations: 1, BanSeconds: 30,
			}},
		},
	}); err != nil {
		t.Fatalf("set config: %v", err)
	}

	sink := &recordingSink{}
	f.mu.Lock()
	f.banSink = sink
	f.mu.Unlock()

	return f, sink
}

// A ban decided in this process is handed to the sink so the kernel can enforce
// it too - that is the whole point of the feature.
func TestBanReachesTheSink(t *testing.T) {
	f, sink := banFirewall(t)

	f.AdmitControl("203.0.113.7:1000")
	if v := f.AdmitControl("203.0.113.7:1000"); !v.Banned {
		t.Fatalf("the source was not banned, got %+v", v)
	}

	if sink.count() != 1 {
		t.Fatalf("the sink was told about %d bans, want 1", sink.count())
	}
	if got := sink.banned[0]; got != netip.MustParseAddr("203.0.113.7") {
		t.Errorf("sink was given %v, want the source address", got)
	}
	if got := sink.ttls[0]; got != 30*time.Second {
		t.Errorf("sink was given a ttl of %v, want the ban's 30s", got)
	}
}

// Strike bans are the other way in, and reach the sink the same way.
func TestStrikeBanReachesTheSink(t *testing.T) {
	f, sink := banFirewall(t)

	cfg := f.Snapshot()
	cfg.AntiAttacker.Strikes = StrikeConfig{
		Enabled: true, ProtocolFailures: 2, BanSeconds: 45, ForgetMs: 300000, MaxTracked: 100,
	}
	if err := f.SetConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}
	// SetConfig rebuilt the sink from the config, which asks for none.
	f.mu.Lock()
	f.banSink = sink
	f.mu.Unlock()

	f.ReportProtocolFailure("198.51.100.4:1")
	f.ReportProtocolFailure("198.51.100.4:1")

	if sink.count() != 1 {
		t.Fatalf("the sink was told about %d strike bans, want 1", sink.count())
	}
	if got := sink.ttls[0]; got != 45*time.Second {
		t.Errorf("ttl = %v, want the strike ban's 45s", got)
	}
}

// The wider tiers share a key that is not an address. They are configured never
// to ban, but nothing that is not an address may reach the host firewall even
// if that changes.
func TestNonAddressKeysNeverReachTheSink(t *testing.T) {
	f, sink := banFirewall(t)

	f.noteBan(globalKey, time.Minute)
	f.noteBan("net:203.0.113.0/24", time.Minute)
	f.noteBan("", time.Minute)
	f.noteBan("203.0.113.7", 0) // no duration is nothing to program

	if sink.count() != 0 {
		t.Fatalf("the sink was handed %d entries it cannot use: %v", sink.count(), sink.banned)
	}
}

// Switching it off has to take frps back out of the host firewall. Addresses
// left behind would outlive the ban that put them there, blocked in the kernel
// and invisible to the dashboard.
func TestTurningItOffDrainsTheSink(t *testing.T) {
	f, sink := banFirewall(t)

	f.mu.Lock()
	f.banCfg = KernelBanConfig{Enabled: true}
	f.applyKernelBanLocked(KernelBanConfig{Enabled: false})
	f.mu.Unlock()

	deadline := time.Now().Add(2 * time.Second)
	for {
		sink.mu.Lock()
		drained := sink.drained
		sink.mu.Unlock()
		if drained > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the old sink was never drained, so its entries stay in the kernel")
		}
		time.Sleep(10 * time.Millisecond)
	}

	// And nothing more is programmed once it is off.
	before := sink.count()
	f.AdmitControl("203.0.113.9:1000")
	f.AdmitControl("203.0.113.9:1000")
	if sink.count() != before {
		t.Error("a ban still reached the sink after the feature was switched off")
	}
}

// Off by default: frps writing to the host firewall is something an operator
// agrees to, not something that starts happening after an upgrade.
func TestKernelBanIsOffByDefault(t *testing.T) {
	f, err := New(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatalf("new firewall: %v", err)
	}
	if got := f.Snapshot().KernelBan; got.Enabled {
		t.Errorf("kernel ban defaults to %+v, want disabled", got)
	}
	if _, ok := f.banSink.(noopSink); !ok {
		t.Errorf("default sink is %T, want the no-op", f.banSink)
	}
}

func TestNewBanSinkHonoursTheConfig(t *testing.T) {
	if _, ok := newBanSink(KernelBanConfig{Enabled: false}).(noopSink); !ok {
		t.Error("a disabled config still built a live sink")
	}
	if _, ok := newBanSink(KernelBanConfig{Enabled: true, Backend: "off"}).(noopSink); !ok {
		t.Error(`backend "off" still built a live sink`)
	}
	if _, ok := newBanSink(KernelBanConfig{Enabled: true, Backend: "nonsense"}).(noopSink); !ok {
		t.Error("an unknown backend built something rather than falling back")
	}
}
