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
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// fakeDNS stands in for the resolver so the tests can move an address the way a
// home connection does, without waiting for a real one to.
type fakeDNS struct {
	mu    sync.Mutex
	addrs map[string][]string
	err   map[string]error
}

func (d *fakeDNS) lookup(_ context.Context, host string) ([]netip.Addr, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if err := d.err[host]; err != nil {
		return nil, err
	}
	out := make([]netip.Addr, 0, len(d.addrs[host]))
	for _, s := range d.addrs[host] {
		out = append(out, netip.MustParseAddr(s))
	}
	return out, nil
}

func (d *fakeDNS) set(host string, addrs ...string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.addrs[host] = addrs
	delete(d.err, host)
}

func (d *fakeDNS) fail(host string, err error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.err[host] = err
}

// ruleFirewall builds a firewall whose rules are under test, with DNS faked and
// the clock in the test's hands.
func ruleFirewall(t *testing.T, rules []Rule) (*Firewall, *fakeDNS, *fakeClock) {
	t.Helper()

	f, err := New(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatalf("new firewall: %v", err)
	}

	clock := &fakeClock{ms: 1_000_000}
	dns := &fakeDNS{addrs: map[string][]string{}, err: map[string]error{}}
	f.domains.nowMs = clock.now
	f.domains.lookup = dns.lookup

	if err := f.SetConfig(Config{
		Enabled: true, ControlPort: true, Default: "allow",
		Rules: rules, Provider: ProviderConfig{Mode: "off"},
	}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	return f, dns, clock
}

// The point of naming a domain in a rule: the address behind it moves, and the
// rule moves with it.
func TestAllowRuleFollowsItsDomain(t *testing.T) {
	f, dns, clock := ruleFirewall(t, []Rule{
		{ID: "office", Action: "allow", CIDR: "office.example.com", Port: "all"},
		{ID: "wall", Action: "deny", CIDR: "*", Port: "all"},
	})
	dns.set("office.example.com", "203.0.113.7")
	f.domains.refresh(context.Background())

	if ok, reason := f.Allow("203.0.113.7:1", 7000); !ok {
		t.Fatalf("the resolved address was denied, reason %q", reason)
	}
	if ok, _ := f.Allow("203.0.113.8:1", 7000); ok {
		t.Fatal("the deny rule below stopped applying to everyone else")
	}

	dns.set("office.example.com", "203.0.113.30")
	clock.advance(61 * time.Second)
	f.domains.refresh(context.Background())

	if ok, _ := f.Allow("203.0.113.30:1", 7000); !ok {
		t.Error("the rule did not follow the domain to its new address")
	}
	if ok, _ := f.Allow("203.0.113.7:1", 7000); ok {
		t.Error("the old address is still allowed after the domain moved")
	}
}

// And the same machinery the other way round, which is the half a whitelist
// could never do: deny a name, and every address behind it is refused.
func TestDenyRuleFollowsItsDomain(t *testing.T) {
	f, dns, clock := ruleFirewall(t, []Rule{
		{ID: "bad", Action: "deny", CIDR: "bad.example.com", Port: "all"},
	})
	dns.set("bad.example.com", "198.51.100.4", "2001:db8::9")
	f.domains.refresh(context.Background())

	for _, ip := range []string{"198.51.100.4:1", "[2001:db8::9]:1"} {
		if ok, _ := f.Allow(ip, 7000); ok {
			t.Errorf("%s was allowed by a deny rule naming its domain", ip)
		}
	}
	if ok, _ := f.Allow("198.51.100.5:1", 7000); !ok {
		t.Error("an address the domain does not resolve to was denied")
	}

	dns.set("bad.example.com", "198.51.100.90")
	clock.advance(61 * time.Second)
	f.domains.refresh(context.Background())

	if ok, _ := f.Allow("198.51.100.90:1", 7000); ok {
		t.Error("the deny rule did not follow the domain to its new address")
	}
	if ok, _ := f.Allow("198.51.100.4:1", 7000); !ok {
		t.Error("the old address is still denied after the domain moved")
	}
}

// A name server hiccup must not quietly change what a rule means. For an allow
// rule that would lock somebody out; for a deny rule it would let them in.
func TestDomainKeepsItsAddressesWhenDNSFails(t *testing.T) {
	f, dns, clock := ruleFirewall(t, []Rule{
		{ID: "bad", Action: "deny", CIDR: "bad.example.com", Port: "all"},
	})
	dns.set("bad.example.com", "198.51.100.4")
	f.domains.refresh(context.Background())

	dns.fail("bad.example.com", errors.New("server misbehaving"))
	clock.advance(61 * time.Second)
	f.domains.refresh(context.Background())

	if ok, _ := f.Allow("198.51.100.4:1", 7000); ok {
		t.Fatal("a failed lookup turned a deny rule into an open door")
	}

	st := f.DomainStatus()
	if len(st) != 1 || st[0].Error == "" {
		t.Errorf("the failure is not visible in the status: %+v", st)
	}
	if len(st[0].Addresses) != 1 || st[0].Addresses[0] != "198.51.100.4" {
		t.Errorf("status does not report what is still matched: %+v", st[0])
	}
}

// Two rules naming the same host are one lookup and one answer.
func TestDomainsSharedAcrossRules(t *testing.T) {
	f, dns, _ := ruleFirewall(t, []Rule{
		{ID: "a", Action: "allow", CIDR: "shared.example.com", Port: "7000"},
		{ID: "b", Action: "deny", CIDR: "shared.example.com", Port: "6000"},
		{ID: "wall", Action: "deny", CIDR: "*", Port: "7000"},
	})
	dns.set("shared.example.com", "203.0.113.7")
	f.domains.refresh(context.Background())

	if st := f.DomainStatus(); len(st) != 1 {
		t.Errorf("the shared host is tracked %d times, want once", len(st))
	}
	if ok, _ := f.Allow("203.0.113.7:1", 7000); !ok {
		t.Error("the allow rule on port 7000 did not match")
	}
	if ok, _ := f.Allow("203.0.113.7:1", 6000); ok {
		t.Error("the deny rule on port 6000 did not match")
	}
}

// Editing one rule must not stop another's domain matching while the next
// lookup is pending.
func TestDomainSurvivesARuleEdit(t *testing.T) {
	f, dns, _ := ruleFirewall(t, []Rule{
		{ID: "office", Action: "allow", CIDR: "office.example.com", Port: "all"},
	})
	dns.set("office.example.com", "203.0.113.7")
	f.domains.refresh(context.Background())

	cfg := f.Snapshot()
	cfg.Rules = append(cfg.Rules, Rule{ID: "extra", Action: "deny", CIDR: "10.0.0.0/8", Port: "all"})
	if err := f.SetConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}

	if !f.domains.has("office.example.com", netip.MustParseAddr("203.0.113.7")) {
		t.Error("a rule edit dropped an address that was already resolved")
	}
}

// Removing the last rule that named a host stops tracking it.
func TestDomainForgottenWhenNoRuleNamesIt(t *testing.T) {
	f, dns, _ := ruleFirewall(t, []Rule{
		{ID: "office", Action: "allow", CIDR: "office.example.com", Port: "all"},
	})
	dns.set("office.example.com", "203.0.113.7")
	f.domains.refresh(context.Background())

	cfg := f.Snapshot()
	cfg.Rules = nil
	if err := f.SetConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}

	if f.domains.has("office.example.com", netip.MustParseAddr("203.0.113.7")) {
		t.Error("a removed rule's domain is still being matched")
	}
	if st := f.DomainStatus(); len(st) != 0 {
		t.Errorf("status still reports %d domains", len(st))
	}
}

// --- trusted ---

// An ordinary allow rule passes the rules layer and nothing more: the source is
// still counted, and can still be refused by the rate limit.
func TestPlainAllowRuleIsStillRateLimited(t *testing.T) {
	f := trustFirewall(t, []Rule{
		{ID: "office", Action: "allow", CIDR: "203.0.113.7", Port: "all"},
	})

	f.AdmitControl("203.0.113.7:1000")
	if f.AdmitControl("203.0.113.7:1000").Allowed {
		t.Error("an allow rule silently switched the rate limit off; only trusted should do that")
	}
}

// Ticking trusted is what turns the counting layers off for a source.
func TestTrustedAllowRuleExemptsFromRateLimiting(t *testing.T) {
	f := trustFirewall(t, []Rule{
		{ID: "office", Action: "allow", CIDR: "203.0.113.7", Port: "all", Trusted: true},
	})

	for i := range 50 {
		if !f.AdmitControl("203.0.113.7:1000").Allowed {
			t.Fatalf("a trusted source was rate limited on attempt %d", i+1)
		}
	}
	f.AdmitControl("203.0.113.8:1000")
	if f.AdmitControl("203.0.113.8:1000").Allowed {
		t.Error("the limit stopped applying to everyone else")
	}
}

// Trust works through a domain too, which is the combination the whole feature
// is for: name the office, tick trusted, stop thinking about its address.
func TestTrustedRuleWorksThroughADomain(t *testing.T) {
	f := trustFirewall(t, []Rule{
		{ID: "office", Action: "allow", CIDR: "office.example.com", Port: "all", Trusted: true},
	})
	dns := &fakeDNS{addrs: map[string][]string{}, err: map[string]error{}}
	f.domains.lookup = dns.lookup
	dns.set("office.example.com", "203.0.113.7")
	f.domains.refresh(context.Background())

	for range 50 {
		if !f.AdmitControl("203.0.113.7:1000").Allowed {
			t.Fatal("a trusted domain's address was rate limited")
		}
	}
}

// Trusted is meaningless on a deny rule and must not become a back door.
func TestTrustedOnADenyRuleExemptsNobody(t *testing.T) {
	f := trustFirewall(t, []Rule{
		{ID: "bad", Action: "deny", CIDR: "203.0.113.7", Port: "9999", Trusted: true},
	})

	f.AdmitControl("203.0.113.7:1000")
	if f.AdmitControl("203.0.113.7:1000").Allowed {
		t.Error("trusted on a deny rule exempted the source from rate limiting")
	}
}

// An expired rule stops granting trust, like it stops doing anything else.
func TestExpiredTrustedRuleStopsExempting(t *testing.T) {
	f := trustFirewall(t, []Rule{
		{ID: "office", Action: "allow", CIDR: "203.0.113.7", Port: "all", Trusted: true, ExpiresAt: 1000},
	})
	f.nowFn = func() int64 { return 2000 }

	f.AdmitControl("203.0.113.7:1000")
	if f.AdmitControl("203.0.113.7:1000").Allowed {
		t.Error("an expired trusted rule is still exempting its source")
	}
}

// trustFirewall arms a control rate limit tight enough that a second attempt is
// refused unless something exempted the source.
func trustFirewall(t *testing.T, rules []Rule) *Firewall {
	t.Helper()

	f, err := New(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatalf("new firewall: %v", err)
	}
	if err := f.SetConfig(Config{
		Enabled: true, ControlPort: true, Default: "allow",
		Rules: rules, Provider: ProviderConfig{Mode: "off"},
		AntiAttacker: AntiAttackerConfig{
			Enabled: true,
			Control: ControlProfile{Protect: true, RateProfile: RateProfile{
				WindowMs: 60000, MaxPerWindow: 1, BanViolations: 2, BanSeconds: 60,
			}},
		},
	}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	return f
}

func TestValidateRuleTarget(t *testing.T) {
	for _, ok := range []string{"", "*", "203.0.113.7", "198.51.100.0/24", "2001:db8::1", "office.example.com", "a-b.co.uk"} {
		if err := ValidateRuleTarget(ok); err != nil {
			t.Errorf("valid target %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{"not a host", "localhost", "-nope.com", "203.0.113.7/99"} {
		if err := ValidateRuleTarget(bad); err == nil {
			t.Errorf("%q was accepted; a typo here silently changes what a rule does", bad)
		}
	}
}
