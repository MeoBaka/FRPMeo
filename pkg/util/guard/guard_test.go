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

package guard

import (
	"strconv"
	"sync"
	"testing"
)

// clock lets the ban tests run without sleeping.
type clock struct {
	mu sync.Mutex
	ms int64
}

func (c *clock) now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ms
}

func (c *clock) advance(ms int64) {
	c.mu.Lock()
	c.ms += ms
	c.mu.Unlock()
}

func newTestGuard(t *testing.T, cfg Config) (*Guard, *clock) {
	t.Helper()
	g, err := New(cfg)
	if err != nil {
		t.Fatalf("new guard: %v", err)
	}
	if g == nil {
		return nil, nil
	}
	c := &clock{ms: 1_000_000}
	g.nowMs = c.now
	return g, c
}

// Nothing configured must cost nothing, so callers need no branch of their own.
func TestNilGuardAdmitsEverything(t *testing.T) {
	g, err := New(Config{})
	if err != nil {
		t.Fatalf("new guard: %v", err)
	}
	if g != nil {
		t.Fatal("an empty config should not produce a guard")
	}
	if !g.Allow("1.2.3.4:5000") {
		t.Fatal("a nil guard must admit everything")
	}
	g.ReportLoginFailure("1.2.3.4:5000") // must not panic
	if g.Banned() != 0 {
		t.Fatal("a nil guard cannot have bans")
	}
}

func TestAllowList(t *testing.T) {
	g, _ := newTestGuard(t, Config{AllowCIDRs: []string{"10.0.0.0/8", "1.2.3.4"}})

	cases := map[string]bool{
		"10.5.5.5:1":          true,
		"1.2.3.4:1":           true,
		"1.2.3.5:1":           false,
		"9.9.9.9:1":           false,
		"[::ffff:10.1.1.1]:1": true, // an ipv4 peer on a dual-stack listener
		"[2001:db8::1]:1":     false,
	}
	for addr, want := range cases {
		if got := g.Allow(addr); got != want {
			t.Errorf("Allow(%q) = %v, want %v", addr, got, want)
		}
	}
}

// A list that silently drops an entry is a list that quietly stops admitting
// somebody, and the first anyone knows is being locked out.
func TestBadCIDRIsAnError(t *testing.T) {
	if _, err := New(Config{AllowCIDRs: []string{"10.0.0.0/8", "nonsense"}}); err == nil {
		t.Fatal("an unparseable allow entry was accepted")
	}
}

// Deciding who somebody is from a string this code could not parse is how an
// allow list turns into an outage. The login still stands behind it.
func TestUnparseablePeerIsAdmitted(t *testing.T) {
	g, _ := newTestGuard(t, Config{AllowCIDRs: []string{"10.0.0.0/8"}})
	if !g.Allow("not-an-address") {
		t.Fatal("an unreadable peer address was refused rather than left to the login")
	}
}

func TestLoginFailuresEarnABan(t *testing.T) {
	g, _ := newTestGuard(t, Config{MaxLoginFailures: 3, BanSeconds: 600})
	const addr = "9.9.9.9:5000"

	for i := range 2 {
		g.ReportLoginFailure(addr)
		if !g.Allow(addr) {
			t.Fatalf("banned after %d failures, want 3", i+1)
		}
	}
	g.ReportLoginFailure(addr)
	if g.Allow(addr) {
		t.Fatal("three failures did not earn a ban")
	}
	if g.Banned() != 1 {
		t.Fatalf("Banned() = %d, want 1", g.Banned())
	}
}

// Locking an administrator out of their own panel is worse than the guessing
// this is meant to stop, so retrying must not push the ban back.
func TestRetryDoesNotExtendTheBan(t *testing.T) {
	g, c := newTestGuard(t, Config{MaxLoginFailures: 2, BanSeconds: 10})
	const addr = "9.9.9.9:5000"

	g.ReportLoginFailure(addr)
	g.ReportLoginFailure(addr) // banned for 10s

	for range 9 {
		c.advance(1000)
		g.ReportLoginFailure(addr) // a client retrying on a timer
		if g.Allow(addr) {
			t.Fatal("admitted while still banned")
		}
	}
	c.advance(1500)
	if !g.Allow(addr) {
		t.Fatal("still banned after the ban expired; the retries extended it")
	}
}

func TestFailuresAreForgottenAfterQuiet(t *testing.T) {
	g, c := newTestGuard(t, Config{MaxLoginFailures: 3, BanSeconds: 600, ForgetSeconds: 60})
	const addr = "9.9.9.9:5000"

	g.ReportLoginFailure(addr)
	g.ReportLoginFailure(addr)
	c.advance(61_000) // quiet for longer than ForgetSeconds

	g.ReportLoginFailure(addr)
	g.ReportLoginFailure(addr)
	if !g.Allow(addr) {
		t.Fatal("old failures survived the quiet period and led to a ban")
	}
}

func TestSourcesAreCountedSeparately(t *testing.T) {
	g, _ := newTestGuard(t, Config{MaxLoginFailures: 2, BanSeconds: 600})

	g.ReportLoginFailure("1.1.1.1:1")
	g.ReportLoginFailure("1.1.1.1:1")
	if g.Allow("1.1.1.1:1") {
		t.Fatal("the guessing source was not banned")
	}
	if !g.Allow("2.2.2.2:1") {
		t.Fatal("one source's ban locked out another")
	}
}

// The allow list decides first: there is no point counting the password
// attempts of somebody who should never have reached the form.
func TestAllowListAndBanTogether(t *testing.T) {
	g, _ := newTestGuard(t, Config{
		AllowCIDRs: []string{"10.0.0.0/8"}, MaxLoginFailures: 2, BanSeconds: 600,
	})
	if g.Allow("9.9.9.9:1") {
		t.Fatal("an address off the list was admitted")
	}
	// And somebody on the list can still earn a ban.
	g.ReportLoginFailure("10.1.1.1:1")
	g.ReportLoginFailure("10.1.1.1:1")
	if g.Allow("10.1.1.1:1") {
		t.Fatal("an allowed address never gets banned for guessing")
	}
}

func TestMaxTrackedStopsGrowth(t *testing.T) {
	g, _ := newTestGuard(t, Config{MaxLoginFailures: 5, MaxTracked: 10})
	for i := range 200 {
		g.ReportLoginFailure("10.0.0." + strconv.Itoa(i%256) + ":1")
	}
	g.mu.Lock()
	n := len(g.entries)
	g.mu.Unlock()
	if n > 10 {
		t.Fatalf("tracked %d sources, cap is 10", n)
	}
}

func TestConcurrentUseIsRaceFree(t *testing.T) {
	g, _ := newTestGuard(t, Config{MaxLoginFailures: 100, BanSeconds: 600})

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			addr := "10.0.0." + strconv.Itoa(i%3) + ":1"
			for range 100 {
				g.ReportLoginFailure(addr)
				g.Allow(addr)
			}
		})
	}
	wg.Wait()
}
