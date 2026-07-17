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
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func newTestFirewall(t *testing.T, rules []Rule) *Firewall {
	t.Helper()
	f, err := New(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatalf("new firewall: %v", err)
	}
	if err := f.SetConfig(true, false, "allow", rules, ProviderConfig{Mode: "off"}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	return f
}

func TestMatchPort(t *testing.T) {
	cases := []struct {
		spec string
		port int
		want bool
	}{
		// any
		{"", 6000, true},
		{"*", 6000, true},
		{"all", 6000, true},
		{"ALL", 6000, true},

		// single
		{"6000", 6000, true},
		{"6000", 6001, false},

		// range, including the low ports the user asked about
		{"0-10", 0, true},
		{"0-10", 10, true},
		{"0-10", 11, false},
		{"6000-6010", 6005, true},
		{"6000-6010", 5999, false},
		{"6000-6010", 6011, false},

		// list of singles and ranges
		{"80,443,7000-7010", 80, true},
		{"80,443,7000-7010", 443, true},
		{"80,443,7000-7010", 7005, true},
		{"80,443,7000-7010", 8080, false},
		{" 80 , 443 ", 443, true}, // spaces are noise

		// A malformed spec must not match: better a rule that visibly does
		// nothing than a deny that silently widens to every port.
		{"abc", 6000, false},
		{"6000-", 6000, false},
		{"70000", 70000, false},
		{"6010-6000", 6005, false}, // reversed range
	}
	for _, c := range cases {
		if got := matchPort(c.spec, c.port); got != c.want {
			t.Errorf("matchPort(%q, %d) = %v, want %v", c.spec, c.port, got, c.want)
		}
	}
}

func TestParsePortSpec(t *testing.T) {
	for _, spec := range []string{"", "*", "all", "6000", "0-10", "80,443,7000-7010", " 80 , 443 "} {
		if err := ParsePortSpec(spec); err != nil {
			t.Errorf("ParsePortSpec(%q) = %v, want nil", spec, err)
		}
	}
	for _, spec := range []string{"abc", "6000-", "-10", "70000", "6010-6000", "80,,443", "80,abc"} {
		if err := ParsePortSpec(spec); err == nil {
			t.Errorf("ParsePortSpec(%q) = nil, want an error", spec)
		}
	}
}

// The point of matching on port: a rule keeps working when the proxy that owns
// the port is re-registered under a different name.
func TestAllowMatchesByPort(t *testing.T) {
	f := newTestFirewall(t, []Rule{
		{ID: "r1", Action: "deny", CIDR: "10.0.0.1", Port: "6000"},
	})

	if ok, _ := f.Allow("10.0.0.1:5555", 6000); ok {
		t.Error("denied ip on the named port should be blocked")
	}
	if ok, _ := f.Allow("10.0.0.1:5555", 6001); !ok {
		t.Error("same ip on another port should pass")
	}
	if ok, _ := f.Allow("10.0.0.2:5555", 6000); !ok {
		t.Error("another ip on the named port should pass")
	}
}

func TestAllowPortRangeAndAny(t *testing.T) {
	f := newTestFirewall(t, []Rule{
		{ID: "range", Action: "deny", CIDR: "10.0.0.1", Port: "6000-6010"},
		{ID: "any-port", Action: "deny", CIDR: "10.0.0.2", Port: "all"},
	})

	for _, port := range []int{6000, 6005, 6010} {
		if ok, _ := f.Allow("10.0.0.1:1", port); ok {
			t.Errorf("port %d is inside the denied range", port)
		}
	}
	if ok, _ := f.Allow("10.0.0.1:1", 6011); !ok {
		t.Error("port just past the range should pass")
	}
	for _, port := range []int{1, 6000, 65535} {
		if ok, _ := f.Allow("10.0.0.2:1", port); ok {
			t.Errorf("all-port rule should cover %d", port)
		}
	}
}

// A blank port means any, so an IP-wide ban stays a one-field rule.
func TestAllowBlankPortIsAnyPort(t *testing.T) {
	f := newTestFirewall(t, []Rule{{ID: "ban", Action: "deny", CIDR: "10.0.0.1"}})
	for _, port := range []int{0, 80, 65535} {
		if ok, _ := f.Allow("10.0.0.1:1", port); ok {
			t.Errorf("blank port should match %d", port)
		}
	}
}

func TestAllowFirstRuleWins(t *testing.T) {
	f := newTestFirewall(t, []Rule{
		{ID: "allow-one", Action: "allow", CIDR: "10.0.0.1", Port: "6000"},
		{ID: "deny-net", Action: "deny", CIDR: "10.0.0.0/8", Port: "all"},
	})

	if ok, reason := f.Allow("10.0.0.1:1", 6000); !ok {
		t.Errorf("the earlier allow should win, got blocked by %s", reason)
	}
	if ok, _ := f.Allow("10.0.0.1:1", 6001); ok {
		t.Error("other ports fall through to the deny")
	}
	if ok, _ := f.Allow("10.1.2.3:1", 6000); ok {
		t.Error("other ips in the net are denied")
	}
}

func TestAllowDefaultPolicy(t *testing.T) {
	f := newTestFirewall(t, nil)
	if err := f.SetConfig(true, false, "deny", nil, ProviderConfig{Mode: "off"}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	if ok, _ := f.Allow("10.0.0.1:1", 6000); ok {
		t.Error("default deny should block an unmatched connection")
	}
}

func TestAllowDisabledFirewallAllowsEverything(t *testing.T) {
	f := newTestFirewall(t, []Rule{{ID: "r", Action: "deny", CIDR: "10.0.0.1", Port: "all"}})
	if err := f.SetConfig(false, false, "deny", []Rule{{ID: "r", Action: "deny", CIDR: "10.0.0.1", Port: "all"}}, ProviderConfig{Mode: "off"}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	if ok, _ := f.Allow("10.0.0.1:1", 6000); !ok {
		t.Error("a disabled firewall must not block")
	}
}

func TestAllowExpiredRuleIsSkipped(t *testing.T) {
	f := newTestFirewall(t, []Rule{
		{ID: "expired", Action: "deny", CIDR: "10.0.0.1", Port: "all", ExpiresAt: 1000},
	})
	f.nowFn = func() int64 { return 2000 }

	if ok, _ := f.Allow("10.0.0.1:1", 6000); !ok {
		t.Error("an expired rule must not block")
	}
}

// The control port is only protected when asked, since a deny default would
// otherwise lock every client out.
func TestAllowControlIsOptIn(t *testing.T) {
	rules := []Rule{{ID: "r", Action: "deny", CIDR: "10.0.0.1", Port: "7000"}}
	f := newTestFirewall(t, rules)

	if ok, _ := f.AllowControl("10.0.0.1:1", 7000); !ok {
		t.Error("control port is not protected by default")
	}

	if err := f.SetConfig(true, true, "allow", rules, ProviderConfig{Mode: "off"}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	if ok, _ := f.AllowControl("10.0.0.1:1", 7000); ok {
		t.Error("with controlPort on, a rule naming the port should block")
	}
	if ok, _ := f.AllowControl("10.0.0.2:1", 7000); !ok {
		t.Error("other ips still get in")
	}
}

func TestAllowIPv6AndCIDR(t *testing.T) {
	f := newTestFirewall(t, []Rule{
		{ID: "v6", Action: "deny", CIDR: "2001:db8::/32", Port: "6000"},
	})

	if ok, _ := f.Allow("[2001:db8::1]:5555", 6000); ok {
		t.Error("ipv6 inside the denied net should be blocked")
	}
	if ok, _ := f.Allow("[2001:db9::1]:5555", 6000); !ok {
		t.Error("ipv6 outside the net should pass")
	}
}

// --- provider self-reference / stampede ---

// Reproduces the reported loop: the provider URL is served through a proxy on
// frps itself, so asking the provider dials one of our own ports, which frps
// sees as a new user connection to ask the provider about. Each question needs
// an answer that needs the question asked again.
func TestAllowSkipsProviderForItsOwnCall(t *testing.T) {
	var queries atomic.Int64
	// Stands in for the panel published through frps: answering means frps has
	// dialed its own port, so Allow runs again for that connection.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries.Add(1)
		_, _ = w.Write([]byte(`{"results":[{"blacklisted":false}]}`))
	}))
	defer srv.Close()

	port := mustPort(t, srv.URL)
	f := newTestFirewall(t, nil)
	if err := f.SetConfig(true, false, "allow", nil, ProviderConfig{
		Mode: "frpcontrol", FRPControlURL: srv.URL, FRPControlAPIKey: "k",
		TimeoutMs: 500, CacheTTLSec: 60,
	}); err != nil {
		t.Fatalf("set config: %v", err)
	}

	if f.selfProviderPort != port {
		t.Fatalf("provider on 127.0.0.1:%d should be recognized as this host, got selfProviderPort %d", port, f.selfProviderPort)
	}

	// frps calling its own provider port: must not ask the provider about it.
	if ok, reason := f.Allow("127.0.0.1:50315", port); !ok {
		t.Fatalf("our own provider call must pass, got blocked by %s", reason)
	}
	if got := queries.Load(); got != 0 {
		t.Fatalf("our own provider call must not trigger a query, got %d", got)
	}

	// Same source, a different port: an ordinary connection, still checked.
	if ok, _ := f.Allow("127.0.0.1:50316", port+1); !ok {
		t.Fatal("unrelated connection should be allowed by the provider")
	}
	if got := queries.Load(); got != 1 {
		t.Fatalf("connections on other ports are still checked, want 1 query got %d", got)
	}
}

// A provider elsewhere must not be mistaken for us, or every port sharing its
// number would quietly lose the reputation check.
func TestSelfProviderNotSetForRemoteHost(t *testing.T) {
	f := newTestFirewall(t, nil)
	if err := f.SetConfig(true, false, "allow", nil, ProviderConfig{
		Mode: "frpcontrol", FRPControlURL: "https://example.invalid:7002", FRPControlAPIKey: "k",
	}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	if f.selfProviderPort != 0 {
		t.Fatalf("a remote provider is not this host, got selfProviderPort %d", f.selfProviderPort)
	}
}

// A burst from one unknown IP used to miss the cache in every goroutine and
// fire one request each.
func TestCheckExternalCollapsesConcurrentQueries(t *testing.T) {
	var queries atomic.Int64
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		queries.Add(1)
		<-release // hold every request open so they overlap
		_, _ = w.Write([]byte(`{"results":[{"blacklisted":true}]}`))
	}))
	defer srv.Close()

	f := newTestFirewall(t, nil)
	if err := f.SetConfig(true, false, "allow", nil, ProviderConfig{
		Mode: "frpcontrol", FRPControlURL: srv.URL, FRPControlAPIKey: "k",
		TimeoutMs: 5000, CacheTTLSec: 60,
	}); err != nil {
		t.Fatalf("set config: %v", err)
	}

	const n = 50
	var wg sync.WaitGroup
	blocked := make([]bool, n)
	for i := range n {
		wg.Go(func() {
			blocked[i] = f.checkExternal("8.8.8.8", f.provider.effective(), f.client)
		})
	}
	time.Sleep(200 * time.Millisecond) // let them all pile onto the same IP
	close(release)
	wg.Wait()

	if got := queries.Load(); got != 1 {
		t.Fatalf("%d concurrent lookups of one IP should be a single query, got %d", n, got)
	}
	for i, b := range blocked {
		if !b {
			t.Fatalf("waiter %d missed the answer the query produced", i)
		}
	}
}

func mustPort(t *testing.T, rawURL string) int {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse %q: %v", rawURL, err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("port of %q: %v", rawURL, err)
	}
	return p
}
