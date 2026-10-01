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
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/util/log"
)

const (
	// defaultDomainRefreshSec is how often a rule's domain is looked up again
	// when the config does not say.
	//
	// A minute is short enough that a home connection which changed address
	// this morning is back in before anyone files a ticket, and long enough
	// that a handful of names is not a name server's problem.
	defaultDomainRefreshSec = 60

	// domainTickSec is how often the refresher wakes to see what is due.
	// Separate from the refresh interval so a config change takes effect
	// without restarting anything.
	domainTickSec = 5

	// domainLookupTimeout bounds one lookup. A name server that hangs must not
	// hold the refresher.
	domainLookupTimeout = 5 * time.Second
)

// DomainStatus is what one rule's domain currently resolves to, for the
// dashboard.
//
// A rule naming a name is only as good as its last lookup, and one that has
// been failing all day is still matching whatever it resolved to yesterday.
// That is the right behavior - see domainResolver.refresh - but it has to be
// visible, or a rule quietly stops meaning what it says.
type DomainStatus struct {
	Domain    string   `json:"domain"`
	Addresses []string `json:"addresses,omitempty"`
	ResolvedS int64    `json:"resolvedSecondsAgo,omitempty"`
	Error     string   `json:"error,omitempty"`
}

// domainResolver keeps the addresses behind every domain named by a rule.
//
// One resolver for all of them rather than one per rule: two rules naming the
// same host are one lookup, and the answer a rule matches against does not
// depend on which rule asked.
type domainResolver struct {
	mu sync.RWMutex

	refreshMs int64

	hosts map[string]*resolvedHost
	// order is how the rules named them, so the status report reads like the
	// rule list rather than like a map.
	order []string

	nowMs  func() int64
	lookup func(ctx context.Context, host string) ([]netip.Addr, error)
}

type resolvedHost struct {
	addrs      []netip.Addr
	resolvedAt int64
	lastErr    string
}

func newDomainResolver(nowMs func() int64) *domainResolver {
	if nowMs == nil {
		nowMs = func() int64 { return time.Now().UnixMilli() }
	}
	return &domainResolver{
		hosts:     make(map[string]*resolvedHost),
		refreshMs: defaultDomainRefreshSec * 1000,
		nowMs:     nowMs,
		lookup:    lookupHost,
	}
}

func lookupHost(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// setHosts replaces the set of names being tracked.
//
// Addresses already resolved for a name that is still in use are kept, so
// editing one rule does not stop another's domain matching for as long as the
// next lookup takes.
func (d *domainResolver) setHosts(hosts []string, refreshSec int) {
	if refreshSec <= 0 {
		refreshSec = defaultDomainRefreshSec
	}

	next := make(map[string]*resolvedHost, len(hosts))
	order := make([]string, 0, len(hosts))

	d.mu.Lock()
	defer d.mu.Unlock()

	for _, host := range hosts {
		if host == "" {
			continue
		}
		if _, seen := next[host]; seen {
			continue
		}
		if prev, ok := d.hosts[host]; ok {
			next[host] = prev
		} else {
			next[host] = &resolvedHost{}
		}
		order = append(order, host)
	}

	d.refreshMs = int64(refreshSec) * 1000
	d.hosts = next
	d.order = order
}

// has reports whether host currently resolves to ip.
func (d *domainResolver) has(host string, ip netip.Addr) bool {
	if host == "" || !ip.IsValid() {
		return false
	}

	d.mu.RLock()
	defer d.mu.RUnlock()

	h := d.hosts[host]
	if h == nil {
		return false
	}
	return slices.Contains(h.addrs, ip)
}

// refresh re-resolves the names that are due.
//
// A lookup that fails leaves the previous addresses in place rather than
// dropping them. For an allow rule the alternative is that a name server
// hiccup quietly removes the exemption, which is the one moment it must not do
// that. For a deny rule it is the same argument the other way round: a name
// that stops resolving must not become a name that stops blocking.
func (d *domainResolver) refresh(ctx context.Context) {
	d.mu.RLock()
	refreshMs := d.refreshMs
	now := d.nowMs()

	due := make([]string, 0, len(d.order))
	for _, host := range d.order {
		h := d.hosts[host]
		if h == nil || h.resolvedAt == 0 || now-h.resolvedAt >= refreshMs {
			due = append(due, host)
		}
	}
	lookup := d.lookup
	d.mu.RUnlock()

	for _, host := range due {
		lookupCtx, cancel := context.WithTimeout(ctx, domainLookupTimeout)
		addrs, err := lookup(lookupCtx, host)
		cancel()

		d.mu.Lock()
		h := d.hosts[host]
		if h == nil {
			d.mu.Unlock()
			continue
		}
		if err != nil {
			// Keep the last known good addresses; only the error is recorded.
			h.lastErr = err.Error()
			d.mu.Unlock()
			continue
		}

		unmapped := make([]netip.Addr, 0, len(addrs))
		for _, a := range addrs {
			unmapped = append(unmapped, a.Unmap())
		}
		sortAddrs(unmapped)

		if !slices.Equal(h.addrs, unmapped) {
			// Worth a line each time: a name that moves is the whole reason
			// rules accept one, and it is rare enough to say so.
			log.Infof("[FW] rule domain %s now resolves to %s", host, joinAddrs(unmapped))
			h.addrs = unmapped
		}
		h.resolvedAt = d.nowMs()
		h.lastErr = ""
		d.mu.Unlock()
	}
}

// status describes every tracked name, in the order the rules named them.
func (d *domainResolver) status() []DomainStatus {
	d.mu.RLock()
	defer d.mu.RUnlock()

	now := d.nowMs()
	out := make([]DomainStatus, 0, len(d.order))

	for _, host := range d.order {
		h := d.hosts[host]
		if h == nil {
			continue
		}
		st := DomainStatus{Domain: host, Error: h.lastErr}
		for _, a := range h.addrs {
			st.Addresses = append(st.Addresses, a.String())
		}
		if h.resolvedAt != 0 {
			st.ResolvedS = (now - h.resolvedAt) / 1000
		}
		out = append(out, st)
	}

	return out
}

// normalizeDomain is how a name in a rule becomes a resolver key. Returns ""
// when the text is not a name at all.
func normalizeDomain(s string) string {
	host := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
	if !plausibleDomain(host) {
		return ""
	}
	return host
}

// plausibleDomain is deliberately loose: it is here to tell a name from a typo,
// not to re-implement the rules for what a name server will accept.
func plausibleDomain(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 || strings.Contains(s, " ") {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return false
		}
		for _, r := range l {
			ok := r == '-' || r == '_' ||
				(r >= '0' && r <= '9') ||
				(r >= 'a' && r <= 'z') ||
				(r >= 'A' && r <= 'Z')
			if !ok {
				return false
			}
		}
	}
	return true
}

// ValidateRuleTarget rejects a rule target that is neither any, an address, a
// CIDR block nor a plausible domain name.
//
// Checked when the config arrives rather than when it is used, because a target
// that does not parse compiles to a rule matching nothing. A deny that silently
// stopped denying, or an allow that silently stopped allowing, is the failure
// this catches - and it has to come back as an error while the person who made
// the typo is still looking at it.
func ValidateRuleTarget(target string) error {
	t := strings.TrimSpace(target)
	if t == "" || t == "*" {
		return nil
	}
	if _, err := netip.ParsePrefix(t); err == nil {
		return nil
	}
	if _, err := netip.ParseAddr(t); err == nil {
		return nil
	}
	if normalizeDomain(t) == "" {
		return fmt.Errorf("rule target %q is not an ip, cidr or domain name", target)
	}
	return nil
}

func sortAddrs(a []netip.Addr) {
	sort.Slice(a, func(i, j int) bool { return a[i].Less(a[j]) })
}

func joinAddrs(a []netip.Addr) string {
	if len(a) == 0 {
		return "nothing"
	}
	parts := make([]string, 0, len(a))
	for _, x := range a {
		parts = append(parts, x.String())
	}
	return strings.Join(parts, ", ")
}
