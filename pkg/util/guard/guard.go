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

// Package guard protects a management interface - the frps dashboard, the frpc
// admin api - with the two things such a port actually needs: a list of who may
// reach it at all, and a ban for whoever keeps guessing the password.
//
// Deliberately much smaller than the firewall frps runs on its public ports.
// That one has to sort strangers from visitors on a port the whole internet is
// invited to, which needs sliding windows, subnet tiers and reputation. A
// management port has a handful of legitimate clients and everybody else is
// wrong, so an allow list does almost all of the work and the rest is counting
// failed logins. Reaching for the larger machinery here would be answering a
// question nobody asked.
package guard

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Config is what a management port is told about who may reach it.
type Config struct {
	// AllowCIDRs lists the peers permitted to connect, as addresses or CIDRs.
	// Empty means everybody, which is the existing behavior.
	//
	// This is the setting that matters. Anything else here narrows an attack;
	// this removes it, because a peer not on the list never reaches the
	// handshake, let alone the login form.
	AllowCIDRs []string

	// MaxLoginFailures bans a source after this many rejected logins. Zero
	// switches the ban off.
	//
	// A low number is right, which is unusual for a threshold. Rates have to
	// guess where normal ends; this does not, because nobody who belongs here
	// gets the password wrong repeatedly - they have it saved or they look it
	// up. Two or three is not impatience, it is the whole distribution.
	MaxLoginFailures int

	// BanSeconds is how long a ban lasts. It is never extended by further
	// attempts: a client that retries on a timer would otherwise hold itself
	// out forever, and locking an administrator out of their own panel is a
	// worse outcome than the guessing this is meant to stop.
	BanSeconds int

	// ForgetSeconds drops a source's failures once it has been quiet this long,
	// so one bad afternoon does not add up to a ban weeks later.
	ForgetSeconds int

	// MaxTracked caps how many sources are remembered.
	MaxTracked int
}

const (
	defaultBanSeconds    = 600
	defaultForgetSeconds = 3600
	defaultMaxTracked    = 8192
)

// Guard decides who may reach a management port.
//
// The zero value is not usable; build one with New. A nil *Guard admits
// everything, so callers with nothing configured need no branch of their own.
type Guard struct {
	allow []netip.Prefix

	maxFailures int
	banMs       int64
	forgetMs    int64
	maxTracked  int

	nowMs func() int64

	mu      sync.Mutex
	entries map[string]*entry
}

type entry struct {
	failures    int
	lastSeen    int64
	bannedUntil int64
}

// New builds a Guard from cfg, or returns nil when cfg asks for nothing - no
// allow list and no ban - so that the common case costs the caller nothing.
//
// An unparseable entry in AllowCIDRs is an error rather than something skipped:
// a list that silently lost one of its entries is a list that quietly stops
// admitting somebody, and the first anyone would know is being locked out.
func New(cfg Config) (*Guard, error) {
	prefixes, err := compileCIDRs(cfg.AllowCIDRs)
	if err != nil {
		return nil, err
	}
	if len(prefixes) == 0 && cfg.MaxLoginFailures <= 0 {
		return nil, nil
	}
	g := &Guard{
		allow:       prefixes,
		maxFailures: cfg.MaxLoginFailures,
		banMs:       int64(orDefault(cfg.BanSeconds, defaultBanSeconds)) * 1000,
		forgetMs:    int64(orDefault(cfg.ForgetSeconds, defaultForgetSeconds)) * 1000,
		maxTracked:  orDefault(cfg.MaxTracked, defaultMaxTracked),
		nowMs:       func() int64 { return time.Now().UnixMilli() },
		entries:     make(map[string]*entry),
	}
	return g, nil
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// compileCIDRs parses the allow list once, at startup, so deciding never parses
// a string.
func compileCIDRs(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			return nil, fmt.Errorf("allowCIDRs: %q is not an IP or CIDR", e)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// Allow reports whether a peer may connect. remoteAddr may carry a port.
//
// An address that cannot be parsed is admitted rather than refused. Deciding
// who somebody is on the strength of a string this code failed to understand is
// how an allow list turns into an outage; the login still stands behind it.
func (g *Guard) Allow(remoteAddr string) bool {
	if g == nil {
		return true
	}
	ip, ok := parseAddr(remoteAddr)
	if !ok {
		return true
	}
	if len(g.allow) > 0 && !contains(g.allow, ip) {
		return false
	}
	if g.maxFailures <= 0 {
		return true
	}

	key := ip.String()
	now := g.nowMs()

	g.mu.Lock()
	defer g.mu.Unlock()

	e := g.entries[key]
	return e == nil || e.bannedUntil <= now
}

// ReportLoginFailure records one rejected login. Wire it to whatever reports
// failed authentication; see http.Server.SetOnAuthFail.
func (g *Guard) ReportLoginFailure(remoteAddr string) {
	if g == nil || g.maxFailures <= 0 {
		return
	}
	ip, ok := parseAddr(remoteAddr)
	if !ok {
		return
	}
	key := ip.String()
	now := g.nowMs()

	g.mu.Lock()
	defer g.mu.Unlock()

	e := g.entries[key]
	if e == nil {
		if len(g.entries) >= g.maxTracked {
			g.pruneLocked(now)
			if len(g.entries) >= g.maxTracked {
				return
			}
		}
		e = &entry{}
		g.entries[key] = e
	}

	// Already serving a ban: count nothing and push nothing back. Retrying is
	// what a client does, and a ban that grows every time it is tested is a ban
	// nobody gets out of.
	if e.bannedUntil > now {
		return
	}
	if e.lastSeen != 0 && now-e.lastSeen > g.forgetMs {
		*e = entry{}
	}
	e.lastSeen = now
	e.failures++

	if e.failures >= g.maxFailures {
		e.bannedUntil = now + g.banMs
		e.failures = 0
	}
}

// Banned reports how many sources are currently serving a ban, for anyone
// wanting to show it.
func (g *Guard) Banned() int {
	if g == nil {
		return 0
	}
	now := g.nowMs()

	g.mu.Lock()
	defer g.mu.Unlock()

	n := 0
	for _, e := range g.entries {
		if e.bannedUntil > now {
			n++
		}
	}
	return n
}

func (g *Guard) pruneLocked(now int64) {
	for k, e := range g.entries {
		if e.bannedUntil > now {
			continue
		}
		if now-e.lastSeen > g.forgetMs {
			delete(g.entries, k)
		}
	}
}

func parseAddr(remoteAddr string) (netip.Addr, bool) {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap(), true
}

func contains(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
