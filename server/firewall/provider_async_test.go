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

// Tests for the reputation provider being asynchronous by default: the paths
// that ask are the ones accepting traffic, so a lookup must not hold them up.
package firewall

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

// slowProvider answers "blacklisted" after delay, and counts how often it was
// asked. Blocked rather than clean because that is the verdict these tests need
// to observe arriving: a clean one is indistinguishable from no answer yet.
func slowProvider(t *testing.T, delay time.Duration) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var queries atomic.Int32
	body := `{"results":[{"blacklisted":true,"reason":"botnet"}]}`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		queries.Add(1)
		time.Sleep(delay)
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &queries
}

func providerFirewall(t *testing.T, url string, blocking bool) *Firewall {
	t.Helper()
	f := newTestFirewall(t, nil)
	if err := f.SetConfig(Config{Enabled: true, Default: "allow", Provider: ProviderConfig{
		Mode: "frpcontrol", FRPControlURL: url, FRPControlAPIKey: "k",
		Blocking: blocking, TimeoutMs: 5000, CacheTTLSec: 60,
	}}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	return f
}

// The point of the change: an unknown address must not stall the caller, because
// the callers are accept loops and a flood is made of unknown addresses.
func TestProviderDoesNotBlockByDefault(t *testing.T) {
	srv, _ := slowProvider(t, 2*time.Second)
	f := providerFirewall(t, srv.URL, false)

	start := time.Now()
	ok, _ := f.Allow("8.8.8.8:1234", 6000)
	elapsed := time.Since(start)

	if elapsed > 500*time.Millisecond {
		t.Fatalf("Allow took %v; the provider is supposed to run in the background", elapsed)
	}
	if !ok {
		t.Fatal("the first connection should fall through to the default policy, not be blocked on a pending lookup")
	}
}

// What the first connection costs: precision on exactly one, and then the
// answer is there.
func TestProviderVerdictArrivesForTheNextConnection(t *testing.T) {
	srv, queries := slowProvider(t, 50*time.Millisecond)
	f := providerFirewall(t, srv.URL, false)

	if ok, _ := f.Allow("8.8.8.8:1234", 6000); !ok {
		t.Fatal("first connection should not have been blocked")
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if ok, reason := f.Allow("8.8.8.8:5678", 6000); !ok {
			if reason == "" {
				t.Fatal("a blocked verdict carried no reason")
			}
			if got := queries.Load(); got != 1 {
				t.Fatalf("provider was asked %d times about one address, want 1", got)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("the background lookup never reached the cache")
}

// A burst from one unknown address must still be a single query - the
// collapsing has to survive the callers no longer waiting.
func TestAsyncProviderStillCollapsesABurst(t *testing.T) {
	srv, queries := slowProvider(t, 300*time.Millisecond)
	f := providerFirewall(t, srv.URL, false)

	for range 50 {
		f.Allow("8.8.8.8:1234", 6000)
	}
	time.Sleep(600 * time.Millisecond)

	if got := queries.Load(); got != 1 {
		t.Fatalf("50 connections from one unknown address produced %d queries, want 1", got)
	}
	if ok, _ := f.Allow("8.8.8.8:1234", 6000); ok {
		t.Fatal("the verdict never landed, so the burst bought nothing")
	}
}

// Blocking stays available for anyone who would rather pay the wait.
func TestProviderBlockingWaitsForTheAnswer(t *testing.T) {
	srv, _ := slowProvider(t, 200*time.Millisecond)
	f := providerFirewall(t, srv.URL, true)

	start := time.Now()
	ok, reason := f.Allow("8.8.8.8:1234", 6000)

	if time.Since(start) < 150*time.Millisecond {
		t.Fatal("Blocking mode returned before the provider could have answered")
	}
	if ok {
		t.Fatal("Blocking mode should have used the provider verdict on the first connection")
	}
	if reason == "" {
		t.Fatal("a blocked verdict carried no reason")
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
