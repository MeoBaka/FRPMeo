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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeProvider is an FRPControl stand-in whose list, speed and availability
// the test controls.
type fakeProvider struct {
	srv *httptest.Server

	queries  atomic.Int32
	inFlight atomic.Int32
	peak     atomic.Int32

	// down makes it answer like frps does for a proxy whose client is gone:
	// with an error instead of a verdict.
	down  atomic.Bool
	delay atomic.Int64 // ns

	mu     sync.Mutex
	listed map[string]string // ip -> reason
}

func newFakeProvider(t *testing.T) *fakeProvider {
	t.Helper()
	p := &fakeProvider{listed: map[string]string{}}
	p.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.queries.Add(1)
		n := p.inFlight.Add(1)
		defer p.inFlight.Add(-1)
		for {
			peak := p.peak.Load()
			if n <= peak || p.peak.CompareAndSwap(peak, n) {
				break
			}
		}

		if d := p.delay.Load(); d > 0 {
			time.Sleep(time.Duration(d))
		}
		if p.down.Load() {
			http.Error(w, "no client serves this port", http.StatusBadGateway)
			return
		}

		var body struct {
			IPs []string `json:"ips"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		ip := ""
		if len(body.IPs) > 0 {
			ip = body.IPs[0]
		}
		p.mu.Lock()
		reason, listed := p.listed[ip]
		p.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]any{
			"results": []any{map[string]any{"ip": ip, "blacklisted": listed, "reason": reason}},
		})
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeProvider) list(ip, reason string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.listed[ip] = reason
}

// fakeSeconds is the firewall's unix-second clock, in the test's hands.
type fakeSeconds struct{ now atomic.Int64 }

func (c *fakeSeconds) get() int64        { return c.now.Load() }
func (c *fakeSeconds) advance(sec int64) { c.now.Add(sec) }

type providerOpts struct {
	controlPort bool
	webPort     bool
	failOpen    bool
	blocking    bool
	ttl         int
}

// providerFirewall is a firewall consulting p, on a clock the test moves.
func providerFirewall(t *testing.T, p *fakeProvider, o providerOpts) (*Firewall, *fakeSeconds) {
	t.Helper()
	f := newTestFirewall(t, nil)
	clock := &fakeSeconds{}
	clock.now.Store(1_000_000)
	f.nowFn = clock.get

	if o.ttl == 0 {
		o.ttl = 60
	}
	if err := f.SetConfig(Config{
		Enabled: true, ControlPort: o.controlPort, WebPort: o.webPort, Default: "allow",
		Provider: ProviderConfig{
			Mode: "frpcontrol", FRPControlURL: p.srv.URL, FRPControlAPIKey: "k",
			FailOpen: o.failOpen, Blocking: o.blocking, TimeoutMs: 5000, CacheTTLSec: o.ttl,
		},
	}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	return f, clock
}

// settle waits for every lookup in progress to land in the cache.
func settle(t *testing.T, f *Firewall) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		f.repMu.Lock()
		n := len(f.repInFlight)
		f.repMu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatal("provider lookups never finished")
}

// --- the lockout this layer used to cause ---

// The production lockout. The provider is published through a proxy that one
// of frps's own clients carries, so while that client is disconnected the
// provider cannot be reached - and the only way it ever comes back is for the
// client to log in again through the control port.
//
// The control port used to treat "provider unavailable" as a refusal, cached
// for ten seconds and renewed by every retry: the client could not get back in
// because the provider was down, and the provider was down because the client
// could not get back in.
func TestControlPortLetsTheProviderClientBackIn(t *testing.T) {
	p := newFakeProvider(t)
	p.down.Store(true) // the client carrying the provider is not connected
	f, clock := providerFirewall(t, p, providerOpts{controlPort: true})

	const client = "198.51.100.7:51000"
	for attempt := range 5 {
		if ok, reason := f.AllowControl(client, 7000); !ok {
			t.Fatalf("login attempt %d was refused (%s): the client carrying the provider can never reconnect", attempt+1, reason)
		}
		settle(t, f)
		clock.advance(retryAfterFailureSec)
	}
	if p.queries.Load() == 0 {
		t.Fatal("the provider was never asked, so this proved nothing")
	}

	// The client is back, the provider answers, and its answers apply again.
	p.down.Store(false)
	p.list("203.0.113.66", "scanner")
	f.AllowControl("203.0.113.66:1", 7000)
	settle(t, f)
	if ok, reason := f.AllowControl("203.0.113.66:2", 7000); ok || reason != "reputation (scanner)" {
		t.Fatalf("got %v %q, want the provider's listing to apply once it answers", ok, reason)
	}
}

// The dashboard is the other door frps keeps for itself - it is where an
// operator goes to fix the provider - so the provider being down does not shut
// it either.
func TestDashboardStaysOpenWhileTheProviderIsDown(t *testing.T) {
	p := newFakeProvider(t)
	p.down.Store(true)
	f, _ := providerFirewall(t, p, providerOpts{webPort: true})

	f.AllowWeb("198.51.100.7:1", 7500)
	settle(t, f)
	if ok, reason := f.AllowWeb("198.51.100.7:2", 7500); !ok {
		t.Fatalf("the dashboard was shut because the provider is down (%s)", reason)
	}
}

// Proxies keep the configured policy: with failOpen off, a visitor the
// provider has never answered for is refused while it cannot be asked.
func TestProxyRefusesUnknownSourcesWhileTheProviderIsDown(t *testing.T) {
	p := newFakeProvider(t)
	p.down.Store(true)
	f, _ := providerFirewall(t, p, providerOpts{})

	f.Allow("203.0.113.9:1", 6000)
	settle(t, f)
	if ok, reason := f.Allow("203.0.113.9:2", 6000); ok || reason != "reputation (provider unavailable)" {
		t.Fatalf("got %v %q, want a refusal naming the outage", ok, reason)
	}

	// And with failOpen on, the same visitor gets through.
	g, _ := providerFirewall(t, p, providerOpts{failOpen: true})
	g.Allow("203.0.113.9:1", 6000)
	settle(t, g)
	if ok, reason := g.Allow("203.0.113.9:2", 6000); !ok {
		t.Fatalf("failOpen on, yet the outage refused a visitor (%s)", reason)
	}
}

// What a source was told survives an outage. A visitor the provider cleared
// minutes ago is not turned away because the provider is momentarily slow or
// gone, and a listed one is not waved in - on a proxy.
func TestAnswersOutliveAnOutage(t *testing.T) {
	p := newFakeProvider(t)
	p.list("203.0.113.66", "botnet")
	f, clock := providerFirewall(t, p, providerOpts{controlPort: true})

	const clean, listed = "198.51.100.20:1", "203.0.113.66:1"
	f.Allow(clean, 6000)
	f.Allow(listed, 6000)
	settle(t, f)

	p.down.Store(true)
	clock.advance(61) // both answers are now stale

	if ok, reason := f.Allow(clean, 6000); !ok {
		t.Fatalf("a cleared visitor was refused while its answer refreshed (%s)", reason)
	}
	if ok, _ := f.Allow(listed, 6000); ok {
		t.Fatal("a listed visitor was let in while its answer refreshed")
	}
	settle(t, f) // the refresh fails

	if ok, reason := f.Allow(clean, 6000); !ok {
		t.Fatalf("a cleared visitor was refused once the refresh failed (%s)", reason)
	}
	if ok, reason := f.Allow(listed, 6000); ok || reason != "reputation (botnet)" {
		t.Fatalf("got %v %q, want the listing to stand through the outage", ok, reason)
	}

	// The control port acts on a listing only while the provider can confirm
	// it: it stops refusing once a refresh has failed.
	if ok, reason := f.AllowControl(listed, 7000); !ok {
		t.Fatalf("the control port acted on a listing the provider cannot confirm (%s)", reason)
	}
}

// While the provider answers, the control port does act on its listings - the
// lenient handling is about the provider's absence, not about its verdicts.
func TestControlPortActsOnAFreshListing(t *testing.T) {
	p := newFakeProvider(t)
	p.list("203.0.113.66", "scanner")
	f, clock := providerFirewall(t, p, providerOpts{controlPort: true})

	f.AllowControl("203.0.113.66:1", 7000)
	settle(t, f)
	if ok, _ := f.AllowControl("203.0.113.66:2", 7000); ok {
		t.Fatal("a listed source logged in while the provider was answering")
	}

	// Stale but not yet refreshed: still acted on while the refresh is out.
	p.delay.Store(int64(300 * time.Millisecond))
	clock.advance(61)
	if ok, _ := f.AllowControl("203.0.113.66:3", 7000); ok {
		t.Fatal("a listing stopped applying the moment it went stale")
	}
	settle(t, f)
	if ok, _ := f.AllowControl("203.0.113.66:4", 7000); ok {
		t.Fatal("a listing the provider just confirmed was not acted on")
	}
}

// The control port never waits on the provider, whatever Blocking says. Its
// listeners decide inline, and one slow lookup would hold up every client.
func TestControlPortNeverWaitsForTheProvider(t *testing.T) {
	p := newFakeProvider(t)
	p.delay.Store(int64(time.Second))
	f, _ := providerFirewall(t, p, providerOpts{controlPort: true, webPort: true, blocking: true})

	start := time.Now()
	f.AllowControl("203.0.113.9:1", 7000)
	f.AllowWeb("203.0.113.10:1", 7500)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("the control port and the dashboard waited %v for the provider", elapsed)
	}
}

// A provider that is down is asked again after retryAfterFailureSec, not for
// every connection - and the wait is per source, so the next attempt finds out
// soon after the provider is back.
func TestFailedLookupsBackOff(t *testing.T) {
	p := newFakeProvider(t)
	p.down.Store(true)
	f, clock := providerFirewall(t, p, providerOpts{})

	for range 20 {
		f.Allow("203.0.113.9:1", 6000)
		settle(t, f)
	}
	if got := p.queries.Load(); got != 1 {
		t.Fatalf("a down provider was asked %d times inside one retry window, want 1", got)
	}

	clock.advance(retryAfterFailureSec)
	f.Allow("203.0.113.9:1", 6000)
	settle(t, f)
	if got := p.queries.Load(); got != 2 {
		t.Fatalf("the provider was asked %d times after the retry window, want 2", got)
	}
}

// Editing a rule must not throw the provider's answers away: in the default
// asynchronous mode that would wave every listed source through once more.
func TestRuleEditKeepsTheProvidersAnswers(t *testing.T) {
	p := newFakeProvider(t)
	p.list("203.0.113.66", "botnet")
	f, _ := providerFirewall(t, p, providerOpts{})

	f.Allow("203.0.113.66:1", 6000)
	settle(t, f)

	cfg := f.Snapshot()
	cfg.Rules = append(cfg.Rules, Rule{ID: "extra", Action: "deny", CIDR: "10.0.0.0/8", Port: "all"})
	if err := f.SetConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}
	if ok, _ := f.Allow("203.0.113.66:2", 6000); ok {
		t.Fatal("a rule edit dropped the provider's listing")
	}
	if got := p.queries.Load(); got != 1 {
		t.Fatalf("a rule edit sent %d queries, want the one from before", got)
	}

	// A different provider - here the same one asked differently - starts over.
	cfg.Provider.TimeoutMs = 4000
	if err := f.SetConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}
	if ok, _ := f.Allow("203.0.113.66:3", 6000); !ok {
		t.Fatal("an answer from before the provider changed was still applied")
	}
}

// The dashboard sends an empty header map where the file had none. That is the
// same provider, and saving it must not throw the answers away.
func TestEmptyHeadersAreNotAProviderChange(t *testing.T) {
	p := newFakeProvider(t)
	p.list("203.0.113.66", "botnet")
	f, _ := providerFirewall(t, p, providerOpts{})

	f.Allow("203.0.113.66:1", 6000)
	settle(t, f)

	cfg := f.Snapshot()
	cfg.Provider.Headers = map[string]string{}
	if err := f.SetConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}
	if ok, _ := f.Allow("203.0.113.66:2", 6000); ok {
		t.Fatal("saving the same provider with an empty header map dropped its answers")
	}
}

// A flood from many addresses must not become the same flood against the
// provider.
func TestConcurrentLookupsAreBounded(t *testing.T) {
	p := newFakeProvider(t)
	p.delay.Store(int64(300 * time.Millisecond))
	f, _ := providerFirewall(t, p, providerOpts{})

	for i := range 4 * maxConcurrentLookups {
		f.Allow(fmt.Sprintf("10.1.%d.%d:1", i/256, i%256), 6000)
	}
	settle(t, f)

	if got := p.peak.Load(); got > maxConcurrentLookups {
		t.Fatalf("%d lookups were out at once, the bound is %d", got, maxConcurrentLookups)
	}
	// The first maxConcurrentLookups addresses are always asked about; the
	// rest only if a slot came free while the burst was still arriving.
	if got := p.queries.Load(); got < maxConcurrentLookups {
		t.Fatalf("only %d queries were sent, the bound of %d should all have been used", got, maxConcurrentLookups)
	}
}

// The cache is bounded too; a full one makes room rather than growing.
func TestReputationCacheIsBounded(t *testing.T) {
	f := newTestFirewall(t, nil)

	f.repMu.Lock()
	defer f.repMu.Unlock()
	for i := range maxReputationEntries {
		f.repCache[fmt.Sprintf("k%d", i)] = repEntry{answered: true}
	}
	f.storeLocked("one-more", repEntry{answered: true, blocked: true})

	if got := len(f.repCache); got != maxReputationEntries {
		t.Fatalf("cache holds %d entries, the bound is %d", got, maxReputationEntries)
	}
	if e, ok := f.repCache["one-more"]; !ok || !e.blocked {
		t.Fatal("the new entry was the one dropped")
	}
}

// Old answers go once they are too old to stand in for the provider, and failed
// lookups once their retry time has come; anything still useful stays.
func TestPruneReputation(t *testing.T) {
	f := newTestFirewall(t, nil)
	clock := &fakeSeconds{}
	clock.now.Store(10_000_000)
	f.nowFn = clock.get
	now := clock.get()

	f.repMu.Lock()
	f.repCache["fresh"] = repEntry{answered: true, fresh: now + 10, next: now + 10}
	f.repCache["stale"] = repEntry{answered: true, fresh: now - 3600, next: now - 3600}
	f.repCache["ancient"] = repEntry{answered: true, fresh: now - maxStaleSec - 1}
	f.repCache["failing"] = repEntry{failed: true, next: now + 5}
	f.repCache["failed-long-ago"] = repEntry{failed: true, next: now - 1}
	f.repCache["pending"] = repEntry{answered: true, fresh: now - maxStaleSec - 1}
	f.repInFlight["pending"] = make(chan struct{})
	f.repMu.Unlock()

	f.pruneReputation()

	f.repMu.Lock()
	defer f.repMu.Unlock()
	for _, keep := range []string{"fresh", "stale", "failing", "pending"} {
		if _, ok := f.repCache[keep]; !ok {
			t.Errorf("%q was pruned", keep)
		}
	}
	for _, gone := range []string{"ancient", "failed-long-ago"} {
		if _, ok := f.repCache[gone]; ok {
			t.Errorf("%q was kept", gone)
		}
	}
}

// The dashboard can tell a provider that answers from one that does not, and
// why - without the request URL, where a custom provider may keep its key.
func TestProviderStatus(t *testing.T) {
	f := newTestFirewall(t, nil)
	if st := f.ProviderStatus(); st.State != "off" {
		t.Fatalf("state with no provider = %q, want off", st.State)
	}

	p := newFakeProvider(t)
	p.list("203.0.113.66", "botnet")
	f, _ = providerFirewall(t, p, providerOpts{})
	if st := f.ProviderStatus(); st.State != "unknown" {
		t.Fatalf("state before any lookup = %q, want unknown", st.State)
	}

	f.Allow("203.0.113.66:1", 6000)
	f.Allow("198.51.100.20:1", 6000)
	settle(t, f)
	st := f.ProviderStatus()
	if st.State != "ok" || st.Answered != 2 || st.Listed != 1 || st.Since == 0 {
		t.Fatalf("status after two answers = %+v", st)
	}

	p.down.Store(true)
	f.Allow("203.0.113.70:1", 6000)
	settle(t, f)
	st = f.ProviderStatus()
	if st.State != "unavailable" || st.LastError == "" {
		t.Fatalf("status after a failed lookup = %+v", st)
	}
	if strings.Contains(st.LastError, p.srv.URL) {
		t.Errorf("the error carries the provider URL: %q", st.LastError)
	}

	p.down.Store(false)
	f.Allow("203.0.113.71:1", 6000)
	settle(t, f)
	if st := f.ProviderStatus(); st.State != "ok" || st.LastError != "" {
		t.Fatalf("status after the provider came back = %+v", st)
	}
}

func TestProviderErrorLeavesTheURLOut(t *testing.T) {
	err := &url.Error{Op: "Get", URL: "https://bl.example/check?apikey=SECRET&ip=1.2.3.4", Err: errors.New("connection refused")}
	if got := providerError(err); strings.Contains(got, "SECRET") || got != "connection refused" {
		t.Fatalf("providerError = %q", got)
	}
}

// --- asynchronous by default ---

// An unknown address must not stall the caller, because the callers are
// accept loops and a flood is made of unknown addresses.
func TestProviderDoesNotBlockByDefault(t *testing.T) {
	p := newFakeProvider(t)
	p.delay.Store(int64(time.Second))
	f, _ := providerFirewall(t, p, providerOpts{})

	start := time.Now()
	ok, _ := f.Allow("8.8.8.8:1234", 6000)
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("Allow took %v; the provider is supposed to run in the background", elapsed)
	}
	if !ok {
		t.Fatal("the first connection should fall through to the default policy, not be blocked on a pending lookup")
	}
}

// What the first connection costs: precision on that one, and then the answer
// is there.
func TestProviderVerdictArrivesForTheNextConnection(t *testing.T) {
	p := newFakeProvider(t)
	p.list("8.8.8.8", "botnet")
	p.delay.Store(int64(50 * time.Millisecond))
	f, _ := providerFirewall(t, p, providerOpts{})

	if ok, _ := f.Allow("8.8.8.8:1234", 6000); !ok {
		t.Fatal("first connection should not have been blocked")
	}
	settle(t, f)
	if ok, reason := f.Allow("8.8.8.8:5678", 6000); ok || reason != "reputation (botnet)" {
		t.Fatalf("got %v %q, want the background answer to apply", ok, reason)
	}
	if got := p.queries.Load(); got != 1 {
		t.Fatalf("provider was asked %d times about one address, want 1", got)
	}
}

// A burst from one unknown address must still be a single query - the
// collapsing has to survive the callers no longer waiting.
func TestAsyncProviderStillCollapsesABurst(t *testing.T) {
	p := newFakeProvider(t)
	p.list("8.8.8.8", "")
	p.delay.Store(int64(300 * time.Millisecond))
	f, _ := providerFirewall(t, p, providerOpts{})

	for range 50 {
		f.Allow("8.8.8.8:1234", 6000)
	}
	settle(t, f)

	if got := p.queries.Load(); got != 1 {
		t.Fatalf("50 connections from one unknown address produced %d queries, want 1", got)
	}
	if ok, _ := f.Allow("8.8.8.8:1234", 6000); ok {
		t.Fatal("the verdict never landed, so the burst bought nothing")
	}
}

// Blocking stays available for anyone who would rather pay the wait.
func TestProviderBlockingWaitsForTheAnswer(t *testing.T) {
	p := newFakeProvider(t)
	p.list("8.8.8.8", "botnet")
	p.delay.Store(int64(200 * time.Millisecond))
	f, _ := providerFirewall(t, p, providerOpts{blocking: true})

	start := time.Now()
	ok, reason := f.Allow("8.8.8.8:1234", 6000)
	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("Blocking mode returned before the provider could have answered")
	}
	if ok || reason != "reputation (botnet)" {
		t.Fatalf("got %v %q, want the provider's verdict on the first connection", ok, reason)
	}
}

// Blocking waits for a first answer only. A refresh runs in the background
// with the old answer standing, so a provider outage does not make every
// connection wait out the timeout.
func TestBlockingDoesNotWaitForARefresh(t *testing.T) {
	p := newFakeProvider(t)
	f, clock := providerFirewall(t, p, providerOpts{blocking: true})

	if ok, _ := f.Allow("198.51.100.20:1", 6000); !ok {
		t.Fatal("a clean source was refused")
	}

	p.delay.Store(int64(time.Second))
	clock.advance(61)
	start := time.Now()
	if ok, _ := f.Allow("198.51.100.20:2", 6000); !ok {
		t.Fatal("a clean source was refused while its answer refreshed")
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("a refresh held the connection for %v", elapsed)
	}
}

// Blocking with a provider that is down: the wait ends with the failure, and
// the source is treated as the configured policy says.
func TestBlockingWithTheProviderDown(t *testing.T) {
	p := newFakeProvider(t)
	p.down.Store(true)
	f, _ := providerFirewall(t, p, providerOpts{blocking: true})

	if ok, reason := f.Allow("203.0.113.9:1", 6000); ok || reason != "reputation (provider unavailable)" {
		t.Fatalf("got %v %q, want a refusal naming the outage", ok, reason)
	}
	// Inside the retry window there is nothing to wait for; still the outage.
	if ok, reason := f.Allow("203.0.113.9:2", 6000); ok || reason != "reputation (provider unavailable)" {
		t.Fatalf("got %v %q inside the retry window", ok, reason)
	}
}

// Blocking is carried through frpcontrol's expansion into a concrete request.
// It was dropped there once, which made the setting silently do nothing.
func TestBlockingSurvivesFRPControlExpansion(t *testing.T) {
	p := ProviderConfig{Mode: "frpcontrol", FRPControlURL: "https://x", FRPControlAPIKey: "k", Blocking: true}
	if !p.effective().Blocking {
		t.Fatal("Blocking was lost expanding frpcontrol into a custom request")
	}
}
