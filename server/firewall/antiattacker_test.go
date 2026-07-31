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
	"strconv"
	"sync"
	"testing"
	"time"
)

// fakeClock drives the limiter so the tests never sleep.
type fakeClock struct {
	mu sync.Mutex
	ms int64
}

func (c *fakeClock) now() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ms
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.ms += d.Milliseconds()
	c.mu.Unlock()
}

// testProfile is small enough to reason about: 3 per 1 s, banned after 2 bad
// windows, ban 10 s.
func testProfile() RateProfile {
	return RateProfile{
		Enabled:       true,
		WindowMs:      1000,
		MaxPerWindow:  3,
		BanViolations: 2,
		BanSeconds:    10,
		IdleForgetMs:  5000,
		MaxTracked:    100,
	}
}

func newTestLimiter() (*limiter, *fakeClock) {
	c := &fakeClock{ms: 1_000_000}
	return newLimiter(c.now), c
}

// admitN runs n attempts and returns how many were allowed.
func admitN(l *limiter, key string, p RateProfile, n int) int {
	allowed := 0
	for range n {
		if l.admit(key, p).Allowed {
			allowed++
		}
	}
	return allowed
}

func TestAdmitDisabledProfileAllowsEverything(t *testing.T) {
	l, _ := newTestLimiter()
	p := testProfile()
	p.Enabled = false
	if got := admitN(l, "1.2.3.4", p, 100); got != 100 {
		t.Fatalf("disabled profile allowed %d/100", got)
	}
	if l.size() != 0 {
		t.Fatalf("disabled profile tracked %d sources, want 0", l.size())
	}
}

func TestAdmitEmptyKeyAllows(t *testing.T) {
	l, _ := newTestLimiter()
	if !l.admit("", testProfile()).Allowed {
		t.Fatal("empty key was refused; an unparseable address must not be counted")
	}
}

func TestAdmitWindowLimit(t *testing.T) {
	l, _ := newTestLimiter()
	p := testProfile()

	if got := admitN(l, "1.2.3.4", p, 3); got != 3 {
		t.Fatalf("allowed %d of the first 3, want 3", got)
	}
	v := l.admit("1.2.3.4", p)
	if v.Allowed {
		t.Fatal("4th attempt in the window was allowed")
	}
	if v.Banned {
		t.Fatal("4th attempt reported a ban; one bad window must only throttle")
	}
	if v.Reason == "" {
		t.Fatal("refusal carried no reason")
	}
	if v.RetryAfter <= 0 || v.RetryAfter > time.Second {
		t.Fatalf("RetryAfter = %v, want the remainder of a 1s window", v.RetryAfter)
	}
}

func TestAdmitWindowRollsOver(t *testing.T) {
	l, c := newTestLimiter()
	p := testProfile()

	admitN(l, "1.2.3.4", p, 4) // fills the window and takes one refusal
	c.advance(1100 * time.Millisecond)

	if got := admitN(l, "1.2.3.4", p, 3); got != 3 {
		t.Fatalf("after the window rolled, allowed %d/3", got)
	}
}

// The distinguishing choice: a burst inside one window is one violation, not
// one per attempt. Otherwise a single page load or reconnect storm would ban a
// real user instantly.
func TestBurstInOneWindowCountsAsOneViolation(t *testing.T) {
	l, _ := newTestLimiter()
	p := testProfile() // BanViolations = 2

	// 50 attempts over the limit, all inside the first window.
	for range 50 {
		if v := l.admit("1.2.3.4", p); v.Banned {
			t.Fatal("banned inside a single window; a burst must only throttle")
		}
	}
}

func TestBanAfterRepeatedBadWindows(t *testing.T) {
	l, c := newTestLimiter()
	p := testProfile() // BanViolations = 2

	admitN(l, "1.2.3.4", p, 4) // window 1 goes over -> violation 1
	c.advance(1100 * time.Millisecond)

	var banned bool
	for range 4 { // window 2 goes over -> violation 2 -> ban
		if l.admit("1.2.3.4", p).Banned {
			banned = true
			break
		}
	}
	if !banned {
		t.Fatal("no ban after two bad windows")
	}
	v := l.admit("1.2.3.4", p)
	if v.Allowed || !v.Banned {
		t.Fatalf("after the ban, verdict = %+v, want refused and banned", v)
	}
	if v.RetryAfter <= 0 || v.RetryAfter > 10*time.Second {
		t.Fatalf("RetryAfter = %v, want at most the 10s ban", v.RetryAfter)
	}
}

// The retry-storm guard: hammering while banned must not push the ban back, or
// a client that retries on a timer can never get out of it.
func TestRetryDuringBanDoesNotExtendIt(t *testing.T) {
	l, c := newTestLimiter()
	p := testProfile()

	admitN(l, "1.2.3.4", p, 4)
	c.advance(1100 * time.Millisecond)
	admitN(l, "1.2.3.4", p, 4) // now banned for 10s

	// Retry once a second for the whole ban, as a real client would.
	for range 9 {
		c.advance(1 * time.Second)
		if l.admit("1.2.3.4", p).Allowed {
			t.Fatal("allowed while still banned")
		}
	}
	c.advance(1500 * time.Millisecond) // ban has now run out

	if !l.admit("1.2.3.4", p).Allowed {
		t.Fatal("still refused after the ban expired; retries extended it")
	}
}

func TestBanExpiryClearsViolations(t *testing.T) {
	l, c := newTestLimiter()
	p := testProfile()

	admitN(l, "1.2.3.4", p, 4)
	c.advance(1100 * time.Millisecond)
	admitN(l, "1.2.3.4", p, 4) // banned
	c.advance(11 * time.Second)

	// One bad window right after the ban must not ban again immediately: the
	// violation count starts from zero.
	for range 4 {
		if l.admit("1.2.3.4", p).Banned {
			t.Fatal("re-banned on the first bad window after a ban expired")
		}
	}
}

func TestIdleForgetsViolations(t *testing.T) {
	l, c := newTestLimiter()
	p := testProfile() // IdleForgetMs = 5000, BanViolations = 2

	admitN(l, "1.2.3.4", p, 4) // violation 1
	c.advance(6 * time.Second) // quiet for longer than IdleForgetMs

	for range 4 {
		if l.admit("1.2.3.4", p).Banned {
			t.Fatal("a violation survived the idle period and led to a ban")
		}
	}
}

func TestSourcesAreCountedSeparately(t *testing.T) {
	l, _ := newTestLimiter()
	p := testProfile()

	admitN(l, "1.2.3.4", p, 4)
	if !l.admit("5.6.7.8", p).Allowed {
		t.Fatal("one source's limit refused a different source")
	}
}

func TestMaxTrackedStopsGrowth(t *testing.T) {
	l, _ := newTestLimiter()
	p := testProfile()
	p.MaxTracked = 10

	for i := range 50 {
		l.admit("10.0.0."+strconv.Itoa(i), p)
	}
	if l.size() > p.MaxTracked {
		t.Fatalf("tracked %d sources, cap is %d", l.size(), p.MaxTracked)
	}
	// Sources admitted before the cap was hit keep being enforced.
	if got := admitN(l, "10.0.0.0", p, 3); got != 2 {
		t.Fatalf("an already-tracked source got %d more attempts, want 2 (1 used)", got)
	}
}

func TestPruneReclaimsIdleSources(t *testing.T) {
	l, c := newTestLimiter()
	p := testProfile()
	p.MaxTracked = 10

	for i := range 10 {
		l.admit("10.0.0."+strconv.Itoa(i), p)
	}
	c.advance(6 * time.Second) // everything is now idle
	l.admit("10.0.1.1", p)     // trips the prune, then fits

	if l.size() > p.MaxTracked {
		t.Fatalf("tracked %d after prune, cap is %d", l.size(), p.MaxTracked)
	}
	if l.size() == 0 {
		t.Fatal("prune removed the source that was just admitted")
	}
}

func TestConcurrentAdmitIsRaceFree(t *testing.T) {
	l, _ := newTestLimiter()
	p := testProfile()
	p.MaxPerWindow = 1000

	var wg sync.WaitGroup
	for i := range 8 {
		wg.Go(func() {
			for range 100 {
				l.admit("10.0.0."+strconv.Itoa(i%3), p)
			}
		})
	}
	wg.Wait()
	if l.size() != 3 {
		t.Fatalf("tracked %d sources, want 3", l.size())
	}
}

func TestClientKeyIgnoresXFFWithoutTrustedList(t *testing.T) {
	got := clientKey("9.9.9.9:1234", "1.2.3.4", nil)
	if got != "9.9.9.9" {
		t.Fatalf("clientKey = %q, want the socket address: an untrusted XFF must not be believed", got)
	}
}

func TestClientKeyUsesXFFFromTrustedProxy(t *testing.T) {
	trusted := compileTrusted([]string{"9.9.9.0/24"})
	if got := clientKey("9.9.9.9:1234", "1.2.3.4, 9.9.9.9", trusted); got != "1.2.3.4" {
		t.Fatalf("clientKey = %q, want the left-most XFF entry 1.2.3.4", got)
	}
}

func TestClientKeyFallsBackOnBadXFF(t *testing.T) {
	trusted := compileTrusted([]string{"9.9.9.9"})
	if got := clientKey("9.9.9.9:1234", "not-an-ip", trusted); got != "9.9.9.9" {
		t.Fatalf("clientKey = %q, want the socket address when the header is unparseable", got)
	}
}

func TestClientKeyUnmapsIPv4MappedAddresses(t *testing.T) {
	if got := clientKey("[::ffff:1.2.3.4]:5000", "", nil); got != "1.2.3.4" {
		t.Fatalf("clientKey = %q, want the unmapped 1.2.3.4", got)
	}
}

func TestClientKeyEmptyForUnparseablePeer(t *testing.T) {
	if got := clientKey("not-an-address", "", nil); got != "" {
		t.Fatalf("clientKey = %q, want empty so the caller lets it through", got)
	}
}

func TestAppliesToScopeAll(t *testing.T) {
	c := AntiAttackerConfig{Scope: "all"}.normalize()
	if !c.appliesTo("bob", "web") {
		t.Fatal(`scope "all" did not apply to a proxy`)
	}
}

func TestAppliesToScopeSelected(t *testing.T) {
	c := AntiAttackerConfig{Scope: "selected", Proxies: []string{"bob/web", "ssh"}}.normalize()

	cases := []struct {
		user, name string
		want       bool
	}{
		{"bob", "web", true},
		{"eve", "web", false}, // same name, different tenant
		{"", "ssh", true},     // bare name, no user configured
		{"bob", "ssh", false}, // bare entry must not match another user's proxy
		{"", "web", false},
	}
	for _, tc := range cases {
		if got := c.appliesTo(tc.user, tc.name); got != tc.want {
			t.Errorf("appliesTo(%q, %q) = %v, want %v", tc.user, tc.name, got, tc.want)
		}
	}
}

func TestNormalizeFillsDefaults(t *testing.T) {
	c := AntiAttackerConfig{Enabled: true}.normalize()
	def := defaultTCPProfile()
	if c.TCP.WindowMs != def.WindowMs || c.TCP.MaxPerWindow != def.MaxPerWindow {
		t.Fatalf("TCP profile = %+v, want XCord's speedy-login defaults %+v", c.TCP, def)
	}
	if c.Scope != "all" {
		t.Fatalf("Scope = %q, want %q", c.Scope, "all")
	}
}

// --- UDP ---

func testUDPProfile() UDPProfile {
	return UDPProfile{
		Enabled:             true,
		WindowMs:            1000,
		MaxPacketsPerWindow: 3,
		MaxBytesPerWindow:   300,
		IdleForgetMs:        5000,
		MaxTracked:          100,
	}
}

func newTestUDPLimiter() (*udpLimiter, *fakeClock) {
	c := &fakeClock{ms: 1_000_000}
	return newUDPLimiter(c.now), c
}

func TestUDPPacketCeiling(t *testing.T) {
	l, _ := newTestUDPLimiter()
	p := testUDPProfile()

	for i := range 3 {
		if !l.admit("1.2.3.4:5000", 10, p) {
			t.Fatalf("packet %d dropped, want forwarded", i+1)
		}
	}
	if l.admit("1.2.3.4:5000", 10, p) {
		t.Fatal("4th packet forwarded past a ceiling of 3")
	}
}

func TestUDPByteCeiling(t *testing.T) {
	l, _ := newTestUDPLimiter()
	p := testUDPProfile()
	p.MaxPacketsPerWindow = 0 // bytes only

	if !l.admit("1.2.3.4:5000", 250, p) {
		t.Fatal("first packet dropped")
	}
	if l.admit("1.2.3.4:5000", 100, p) {
		t.Fatal("packet forwarded past the 300-byte ceiling")
	}
	// A packet that still fits is not collateral damage from the big one.
	if !l.admit("1.2.3.4:5000", 40, p) {
		t.Fatal("a packet that fits within the ceiling was dropped")
	}
}

func TestUDPWindowRollsOver(t *testing.T) {
	l, c := newTestUDPLimiter()
	p := testUDPProfile()

	for range 4 {
		l.admit("1.2.3.4:5000", 10, p)
	}
	c.advance(1100 * time.Millisecond)

	if !l.admit("1.2.3.4:5000", 10, p) {
		t.Fatal("still dropping after the window rolled over")
	}
}

func TestUDPSourcesCountedSeparately(t *testing.T) {
	l, _ := newTestUDPLimiter()
	p := testUDPProfile()

	for range 4 {
		l.admit("1.2.3.4:5000", 10, p)
	}
	if !l.admit("5.6.7.8:5000", 10, p) {
		t.Fatal("one source's rate dropped another source's packet")
	}
}

// The global tier is the one a forged source address cannot get around.
func TestUDPGlobalCeilingAppliesAcrossSources(t *testing.T) {
	l, _ := newTestUDPLimiter()
	p := testUDPProfile()
	p.MaxPacketsPerWindow = 0
	p.MaxBytesPerWindow = 0
	p.GlobalMaxPacketsPerWindow = 5

	for i := range 5 {
		if !l.admit("10.0.0."+strconv.Itoa(i), 10, p) {
			t.Fatalf("packet %d from a fresh source dropped below the global ceiling", i+1)
		}
	}
	if l.admit("10.0.0.99", 10, p) {
		t.Fatal("a brand new source got through after the global ceiling was reached")
	}
}

func TestUDPGlobalCeilingDoesNotTrackSources(t *testing.T) {
	l, _ := newTestUDPLimiter()
	p := testUDPProfile()
	p.MaxPacketsPerWindow = 0
	p.MaxBytesPerWindow = 0
	p.GlobalMaxPacketsPerWindow = 1000

	for i := range 200 {
		l.admit("10.0.0."+strconv.Itoa(i), 10, p)
	}
	// With no per-source ceiling there is nothing to remember, and a flood of
	// forged sources must not be able to grow the table.
	if l.size() != 0 {
		t.Fatalf("tracked %d sources with no per-source ceiling configured, want 0", l.size())
	}
}

func TestUDPZeroCeilingsMeanUnlimited(t *testing.T) {
	l, _ := newTestUDPLimiter()
	p := UDPProfile{Enabled: true, WindowMs: 1000, IdleForgetMs: 5000, MaxTracked: 100}

	for i := range 1000 {
		if !l.admit("1.2.3.4:5000", 1000, p) {
			t.Fatalf("packet %d dropped with every ceiling left at zero", i+1)
		}
	}
}

func TestUDPDisabledForwardsEverything(t *testing.T) {
	l, _ := newTestUDPLimiter()
	p := testUDPProfile()
	p.Enabled = false

	for range 100 {
		if !l.admit("1.2.3.4:5000", 9999, p) {
			t.Fatal("a disabled profile dropped a packet")
		}
	}
}

func TestUDPMaxTrackedStopsGrowth(t *testing.T) {
	l, _ := newTestUDPLimiter()
	p := testUDPProfile()
	p.MaxTracked = 10

	for i := range 100 {
		l.admit("10.0.0."+strconv.Itoa(i), 10, p)
	}
	if l.size() > p.MaxTracked {
		t.Fatalf("tracked %d sources, cap is %d", l.size(), p.MaxTracked)
	}
}

func TestAdmitUDPOffByDefault(t *testing.T) {
	f := newTestFirewall(t, nil)
	for range 100 {
		if !f.AdmitUDP("1.2.3.4:5000", 9999, "", "game") {
			t.Fatal("UDP rate limiting acted while AntiAttacker was off")
		}
	}
}

func TestAdmitUDPLimits(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		UDP:     UDPProfile{Enabled: true, WindowMs: 60000, MaxPacketsPerWindow: 2},
	})
	f.AdmitUDP("1.2.3.4:5000", 10, "", "game")
	f.AdmitUDP("1.2.3.4:5000", 10, "", "game")
	if f.AdmitUDP("1.2.3.4:5000", 10, "", "game") {
		t.Fatal("3rd packet forwarded past a ceiling of 2")
	}
}

func TestAdmitUDPRespectsScope(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true, Scope: "selected", Proxies: []string{"bob/game"},
		UDP: UDPProfile{Enabled: true, WindowMs: 60000, MaxPacketsPerWindow: 1},
	})
	f.AdmitUDP("1.2.3.4:5000", 10, "bob", "game")
	if f.AdmitUDP("1.2.3.4:5000", 10, "bob", "game") {
		t.Fatal("the in-scope proxy was not limited")
	}
	if !f.AdmitUDP("1.2.3.4:5000", 10, "bob", "other") {
		t.Fatal("an out-of-scope proxy was limited")
	}
}

// --- Firewall-level wiring ---

func newAAFirewall(t *testing.T, aa AntiAttackerConfig) *Firewall {
	t.Helper()
	f := newTestFirewall(t, nil)
	cfg := f.Snapshot()
	cfg.AntiAttacker = aa
	if err := f.SetConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}
	return f
}

func TestAdmitTCPOffByDefault(t *testing.T) {
	f := newTestFirewall(t, nil)
	for range 50 {
		if v := f.AdmitTCP("1.2.3.4:1000", "", "web"); !v.Allowed {
			t.Fatal("rate limiting acted while AntiAttacker was off")
		}
	}
}

func TestAdmitTCPMasterSwitchGatesTheProfile(t *testing.T) {
	// Profile on, master off: still nothing happens.
	f := newAAFirewall(t, AntiAttackerConfig{
		TCP: RateProfile{Enabled: true, MaxPerWindow: 1},
	})
	for range 10 {
		if v := f.AdmitTCP("1.2.3.4:1000", "", "web"); !v.Allowed {
			t.Fatal("profile acted with the master switch off")
		}
	}
}

func TestAdmitTCPLimits(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		TCP:     RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 3, BanViolations: 99},
	})
	for i := range 3 {
		if v := f.AdmitTCP("1.2.3.4:1000", "", "web"); !v.Allowed {
			t.Fatalf("attempt %d refused, want allowed", i+1)
		}
	}
	if v := f.AdmitTCP("1.2.3.4:1000", "", "web"); v.Allowed {
		t.Fatal("4th connection allowed past a limit of 3")
	}
}

func TestAdmitTCPScopeSelectedSkipsOtherProxies(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true, Scope: "selected", Proxies: []string{"bob/web"},
		TCP: RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1, BanViolations: 99},
	})
	f.AdmitTCP("1.2.3.4:1000", "bob", "web")
	if v := f.AdmitTCP("1.2.3.4:1000", "bob", "web"); v.Allowed {
		t.Fatal("the in-scope proxy was not limited")
	}
	if v := f.AdmitTCP("1.2.3.4:1000", "bob", "ssh"); !v.Allowed {
		t.Fatal("an out-of-scope proxy was limited")
	}
}

func TestAdmitHTTPLimitsAndReportsRetryAfter(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		HTTP: HTTPProfile{RateProfile: RateProfile{
			Enabled: true, WindowMs: 60000, MaxPerWindow: 2, BanViolations: 99,
		}},
	})
	f.AdmitHTTP("1.2.3.4:1000", "", "", "web")
	f.AdmitHTTP("1.2.3.4:1000", "", "", "web")

	v := f.AdmitHTTP("1.2.3.4:1000", "", "", "web")
	if v.Allowed {
		t.Fatal("3rd request allowed past a limit of 2")
	}
	if s := f.RetryAfterSeconds(v); s < 1 {
		t.Fatalf("RetryAfterSeconds = %d, want at least 1 so the header is usable", s)
	}
}

func TestAdmitHTTPUsesXFFOnlyFromTrustedProxy(t *testing.T) {
	base := RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1, BanViolations: 99}

	// Untrusted: both requests count against the one socket address.
	f := newAAFirewall(t, AntiAttackerConfig{Enabled: true, HTTP: HTTPProfile{RateProfile: base}})
	f.AdmitHTTP("9.9.9.9:1000", "1.1.1.1", "", "web")
	if v := f.AdmitHTTP("9.9.9.9:1000", "2.2.2.2", "", "web"); v.Allowed {
		t.Fatal("a spoofed X-Forwarded-For split one source into two without a trusted list")
	}

	// Trusted: they are different clients and both get their first request.
	f2 := newAAFirewall(t, AntiAttackerConfig{Enabled: true, HTTP: HTTPProfile{
		RateProfile: base, TrustedProxies: []string{"9.9.9.9"},
	}})
	f2.AdmitHTTP("9.9.9.9:1000", "1.1.1.1", "", "web")
	if v := f2.AdmitHTTP("9.9.9.9:1000", "2.2.2.2", "", "web"); !v.Allowed {
		t.Fatal("two clients behind a trusted proxy were counted as one")
	}
}

func TestRetryAfterSecondsHonorsOverride(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		HTTP: HTTPProfile{
			RateProfile:   RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1, BanViolations: 99},
			RetryAfterSec: 42,
		},
	})
	f.AdmitHTTP("1.2.3.4:1000", "", "", "web")
	v := f.AdmitHTTP("1.2.3.4:1000", "", "", "web")
	if got := f.RetryAfterSeconds(v); got != 42 {
		t.Fatalf("RetryAfterSeconds = %d, want the configured 42", got)
	}
}

func TestSetConfigClearsCounters(t *testing.T) {
	aa := AntiAttackerConfig{
		Enabled: true,
		TCP:     RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1, BanViolations: 99},
	}
	f := newAAFirewall(t, aa)
	f.AdmitTCP("1.2.3.4:1000", "", "web")
	if v := f.AdmitTCP("1.2.3.4:1000", "", "web"); v.Allowed {
		t.Fatal("limit did not apply before the config change")
	}

	cfg := f.Snapshot()
	if err := f.SetConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}
	if v := f.AdmitTCP("1.2.3.4:1000", "", "web"); !v.Allowed {
		t.Fatal("counters survived a config change; they were built against the old thresholds")
	}
}

func TestAntiAttackerSurvivesReload(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "fw.json")

	f, err := New(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	cfg := f.Snapshot()
	cfg.Enabled = true
	cfg.AntiAttacker = AntiAttackerConfig{
		Enabled: true, Scope: "selected", Proxies: []string{"bob/web"},
		TCP:  RateProfile{Enabled: true, MaxPerWindow: 7},
		HTTP: HTTPProfile{TrustedProxies: []string{"10.0.0.0/8"}},
	}
	if err := f.SetConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}

	f2, err := New(path)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	got := f2.Snapshot().AntiAttacker
	if !got.Enabled || got.Scope != "selected" || len(got.Proxies) != 1 || got.Proxies[0] != "bob/web" {
		t.Fatalf("scope did not survive the reload: %+v", got)
	}
	if got.TCP.MaxPerWindow != 7 {
		t.Fatalf("TCP.MaxPerWindow = %d, want 7", got.TCP.MaxPerWindow)
	}
	if len(got.HTTP.TrustedProxies) != 1 {
		t.Fatalf("TrustedProxies did not survive the reload: %+v", got.HTTP.TrustedProxies)
	}
}

// --- control port ---

func TestAdmitControlOffByDefault(t *testing.T) {
	f := newTestFirewall(t, nil)
	for range 500 {
		if !f.AdmitControl("1.2.3.4:1000").Allowed {
			t.Fatal("the control port was rate limited while AntiAttacker was off")
		}
	}
}

// Turning AntiAttacker on for proxies must not start refusing frpc clients:
// that would take every tunnel down, which is worse than the flood.
func TestAdmitControlNeedsItsOwnSwitch(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		TCP:     RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1},
		Control: ControlProfile{RateProfile: RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1}},
		// Protect left false
	})
	for range 10 {
		if !f.AdmitControl("1.2.3.4:1000").Allowed {
			t.Fatal("the control port was limited without Control.Protect")
		}
	}
}

func TestAdmitControlLimits(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		Control: ControlProfile{
			Protect:     true,
			RateProfile: RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 3, BanViolations: 99},
		},
	})
	for i := range 3 {
		if !f.AdmitControl("1.2.3.4:1000").Allowed {
			t.Fatalf("connection %d refused, want allowed", i+1)
		}
	}
	if f.AdmitControl("1.2.3.4:1000").Allowed {
		t.Fatal("4th connection allowed past a limit of 3")
	}
}

// One frpc address is a control connection, a pool of work connections and
// possibly user traffic to a proxy. Sharing one counter would let any of those
// starve the others.
func TestControlAndProxyCountersAreSeparate(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		TCP:     RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1, BanViolations: 99},
		Control: ControlProfile{
			Protect:     true,
			RateProfile: RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1, BanViolations: 99},
		},
	})
	f.AdmitTCP("1.2.3.4:1000", "", "web")
	if f.AdmitTCP("1.2.3.4:1000", "", "web").Allowed {
		t.Fatal("the proxy limit did not apply")
	}
	if !f.AdmitControl("1.2.3.4:1000").Allowed {
		t.Fatal("proxy traffic used up the control port's budget for the same address")
	}
}

func TestControlProfileDefaultIsLooserThanTCP(t *testing.T) {
	c := AntiAttackerConfig{}.normalize()
	if c.Control.MaxPerWindow <= c.TCP.MaxPerWindow {
		t.Fatalf("control default %d is not above the tcp default %d - an frpc pool would trip it",
			c.Control.MaxPerWindow, c.TCP.MaxPerWindow)
	}
}

// --- dashboard and ssh gateway ---

func TestAdmitWebAndSSHOffByDefault(t *testing.T) {
	f := newTestFirewall(t, nil)
	for range 200 {
		if !f.AdmitWeb("1.2.3.4:1000").Allowed {
			t.Fatal("the dashboard was rate limited while AntiAttacker was off")
		}
		if !f.AdmitSSH("1.2.3.4:1000").Allowed {
			t.Fatal("the ssh gateway was rate limited while AntiAttacker was off")
		}
	}
}

func TestAdmitWebNeedsItsOwnSwitch(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		Control: ControlProfile{Protect: true, RateProfile: RateProfile{Enabled: true, MaxPerWindow: 1}},
		Web:     ControlProfile{RateProfile: RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1}},
	})
	for range 10 {
		if !f.AdmitWeb("1.2.3.4:1000").Allowed {
			t.Fatal("the dashboard was limited without Web.Protect - protecting the control port must not lock the UI")
		}
	}
}

func TestAdmitWebLimits(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		Web: ControlProfile{
			Protect:     true,
			RateProfile: RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 2, BanViolations: 99},
		},
	})
	f.AdmitWeb("1.2.3.4:1000")
	f.AdmitWeb("1.2.3.4:1000")
	if f.AdmitWeb("1.2.3.4:1000").Allowed {
		t.Fatal("3rd dashboard connection allowed past a limit of 2")
	}
}

func TestAdmitSSHLimits(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		SSH: ControlProfile{
			Protect:     true,
			RateProfile: RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 2, BanViolations: 99},
		},
	})
	f.AdmitSSH("1.2.3.4:1000")
	f.AdmitSSH("1.2.3.4:1000")
	if f.AdmitSSH("1.2.3.4:1000").Allowed {
		t.Fatal("3rd ssh connection allowed past a limit of 2")
	}
}

// Four doors, four budgets. Hammering one must not spend another's.
func TestControlWebSSHAndProxyCountersAreSeparate(t *testing.T) {
	one := RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1, BanViolations: 99}
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		TCP:     one,
		Control: ControlProfile{Protect: true, RateProfile: one},
		Web:     ControlProfile{Protect: true, RateProfile: one},
		SSH:     ControlProfile{Protect: true, RateProfile: one},
	})
	const addr = "1.2.3.4:1000"

	// Spend the whole budget on the dashboard.
	f.AdmitWeb(addr)
	if f.AdmitWeb(addr).Allowed {
		t.Fatal("the dashboard limit did not apply")
	}

	for name, allowed := range map[string]bool{
		"control": f.AdmitControl(addr).Allowed,
		"ssh":     f.AdmitSSH(addr).Allowed,
		"proxy":   f.AdmitTCP(addr, "", "web").Allowed,
	} {
		if !allowed {
			t.Errorf("dashboard traffic used up the %s budget for the same address", name)
		}
	}
}

// A password guesser gets far less room than an frpc pool needs.
func TestWebAndSSHDefaultsAreTighterThanControl(t *testing.T) {
	c := AntiAttackerConfig{}.normalize()
	if c.Web.MaxPerWindow >= c.Control.MaxPerWindow {
		t.Errorf("web default %d is not below the control default %d", c.Web.MaxPerWindow, c.Control.MaxPerWindow)
	}
	if c.SSH.MaxPerWindow >= c.Control.MaxPerWindow {
		t.Errorf("ssh default %d is not below the control default %d", c.SSH.MaxPerWindow, c.Control.MaxPerWindow)
	}
	// ...but the dashboard still has to survive a page load, which opens
	// several connections for its assets before anyone types anything.
	if c.Web.MaxPerWindow < 20 {
		t.Errorf("web default %d is too tight for a single-page app's asset requests", c.Web.MaxPerWindow)
	}
}

func TestValidateAntiAttacker(t *testing.T) {
	ok := AntiAttackerConfig{HTTP: HTTPProfile{TrustedProxies: []string{"10.0.0.0/8", "1.2.3.4", "::1", ""}}}
	if err := ValidateAntiAttacker(ok); err != nil {
		t.Fatalf("valid trusted proxies rejected: %v", err)
	}
	bad := AntiAttackerConfig{HTTP: HTTPProfile{TrustedProxies: []string{"10.0.0.0/8", "nonsense"}}}
	if err := ValidateAntiAttacker(bad); err == nil {
		t.Fatal("an unparseable trusted proxy was accepted; it would be dropped silently")
	}
}

func TestNormalizeKeepsIdleForgetAtLeastOneWindow(t *testing.T) {
	c := AntiAttackerConfig{TCP: RateProfile{WindowMs: 30000, IdleForgetMs: 1000}}.normalize()
	if c.TCP.IdleForgetMs < c.TCP.WindowMs {
		t.Fatalf("IdleForgetMs = %d, must not be below WindowMs = %d or counters reset mid-window",
			c.TCP.IdleForgetMs, c.TCP.WindowMs)
	}
}
