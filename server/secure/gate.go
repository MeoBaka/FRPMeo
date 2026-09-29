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

// Package secure locks a proxy behind a key. A visitor proves the key - by
// opening a link, by an HTTP request, or on the first line of a connection -
// and frps forwards nothing to the backend for anyone who has not.
//
// Most clients cannot send anything of their own ahead of the protocol they
// speak (a game, RDP, SSH), so proving the key usually unlocks the visitor's IP
// for a while rather than a single connection. The unit of trust is therefore
// an address: everyone behind the same NAT shares an unlock.
package secure

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

const (
	// failureMemory drops a source's wrong keys once it has been quiet this
	// long, so one bad afternoon does not add up to a ban weeks later.
	failureMemory = time.Hour

	// pruneIdle is how long a source must have been quiet to be forgotten when
	// the table is full.
	pruneIdle = 10 * time.Minute

	// maxTracked caps the sources remembered for rate limits and bans.
	maxTracked = 8192

	// maxUnlocked caps the unlocked addresses. Every entry took a valid key, so
	// this is about memory rather than about an attacker.
	maxUnlocked = 8192
)

// Gate enforces one proxy's secure access settings. It is safe for concurrent
// use.
type Gate struct {
	title  string
	keySum [sha256.Size]byte

	// The ways the key may be presented, narrowed to what the proxy type can
	// carry.
	link, http, line bool

	unlockTTL   time.Duration
	allow       []netip.Prefix
	trusted     []netip.Prefix
	maxFailures int
	maxAttempts int
	banDuration time.Duration

	cookieName string
	cookieKey  []byte

	now func() time.Time

	mu       sync.Mutex
	unlocked map[netip.Addr]time.Time
	sources  map[netip.Addr]*source
}

// source is what a gate remembers about an address that is not unlocked.
type source struct {
	windowStart time.Time
	attempts    int
	failures    int
	lastFailure time.Time
	lastSeen    time.Time
	bannedUntil time.Time
}

// NewGate builds the gate for the proxy called name, of type proxyType. cfg is
// expected to have been validated; an address that still fails to parse is an
// error rather than an entry silently lost from a list.
func NewGate(name, proxyType string, cfg *v1.SecureConfig) (*Gate, error) {
	allow, err := parsePrefixes(cfg.AllowIPs)
	if err != nil {
		return nil, fmt.Errorf("secure.allowIPs: %w", err)
	}
	trusted, err := parsePrefixes(cfg.TrustedIPs)
	if err != nil {
		return nil, fmt.Errorf("secure.trustedIPs: %w", err)
	}
	nameSum := sha256.Sum256([]byte(name))
	// Tied to the proxy and its key: changing the key logs every browser out.
	cookieKey := sha256.Sum256([]byte("frp-secure-cookie\x00" + name + "\x00" + cfg.Key))
	return &Gate{
		title:       cfg.Title,
		keySum:      sha256.Sum256([]byte(cfg.Key)),
		link:        cfg.HasMethod(v1.SecureMethodLink),
		http:        cfg.HasMethod(v1.SecureMethodHTTP),
		line:        cfg.HasMethod(v1.SecureMethodLine) && v1.SecureLineApplies(proxyType),
		unlockTTL:   seconds(orDefault(cfg.UnlockSeconds, v1.DefaultSecureUnlockSeconds)),
		allow:       allow,
		trusted:     trusted,
		maxFailures: threshold(cfg.AntiSpam.MaxFailures, v1.DefaultSecureMaxFailures),
		maxAttempts: threshold(cfg.AntiSpam.MaxAttemptsPerMinute, v1.DefaultSecureMaxAttemptsPerMinute),
		banDuration: seconds(orDefault(cfg.AntiSpam.BanSeconds, v1.DefaultSecureBanSeconds)),
		cookieName:  "frp_secure_" + hex.EncodeToString(nameSum[:6]),
		cookieKey:   cookieKey[:],
		now:         time.Now,
		unlocked:    make(map[netip.Addr]time.Time),
		sources:     make(map[netip.Addr]*source),
	}, nil
}

// TakesRequests reports whether the key can arrive in an HTTP request - a link
// or a request carrying it.
func (g *Gate) TakesRequests() bool {
	return g.link || g.http
}

// HasOtherWayIn reports whether a visitor could get in without an HTTP
// request: by a key line, or from a trusted address.
func (g *Gate) HasOtherWayIn() bool {
	return g.line || len(g.trusted) > 0
}

// standing is where a source stands before anything it sends is read.
type standing int

const (
	// unknown sources have to prove the key.
	unknown standing = iota

	// admitted sources go straight through: trusted, or unlocked.
	admitted

	// refused sources are outside the allow list, or banned.
	refused
)

func (g *Gate) standingOf(ip netip.Addr) standing {
	if len(g.allow) > 0 && !contains(g.allow, ip) {
		return refused
	}
	if contains(g.trusted, ip) {
		return admitted
	}
	now := g.now()

	g.mu.Lock()
	defer g.mu.Unlock()

	if until, ok := g.unlocked[ip]; ok {
		if until.After(now) {
			return admitted
		}
		delete(g.unlocked, ip)
	}
	if s := g.sources[ip]; s != nil && s.bannedUntil.After(now) {
		return refused
	}
	return unknown
}

// noteAttempt counts one try at getting in by a source that is not admitted,
// and reports false once the source has tried too often and is banned for it.
func (g *Gate) noteAttempt(ip netip.Addr) bool {
	if g.maxAttempts <= 0 {
		return true
	}
	now := g.now()

	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sourceLocked(ip, now)
	if s == nil {
		return true
	}
	if now.Sub(s.windowStart) >= time.Minute {
		s.windowStart = now
		s.attempts = 0
	}
	s.attempts++
	if s.attempts > g.maxAttempts {
		s.bannedUntil = now.Add(g.banDuration)
		s.attempts = 0
		return false
	}
	return true
}

// noteFailure records a wrong key.
func (g *Gate) noteFailure(ip netip.Addr) {
	if g.maxFailures <= 0 {
		return
	}
	now := g.now()

	g.mu.Lock()
	defer g.mu.Unlock()

	s := g.sourceLocked(ip, now)
	if s == nil {
		return
	}
	if now.Sub(s.lastFailure) > failureMemory {
		s.failures = 0
	}
	s.lastFailure = now
	s.failures++
	if s.failures >= g.maxFailures {
		s.bannedUntil = now.Add(g.banDuration)
		s.failures = 0
	}
}

// unlock admits ip for the unlock duration and forgives what it got wrong on
// the way there.
func (g *Gate) unlock(ip netip.Addr) {
	now := g.now()

	g.mu.Lock()
	defer g.mu.Unlock()

	if _, ok := g.unlocked[ip]; !ok && len(g.unlocked) >= maxUnlocked {
		g.pruneUnlockedLocked(now)
	}
	g.unlocked[ip] = now.Add(g.unlockTTL)
	if s := g.sources[ip]; s != nil {
		s.attempts, s.failures = 0, 0
	}
}

// pruneUnlockedLocked drops expired unlocks and, if that frees nothing, the one
// closest to expiring.
func (g *Gate) pruneUnlockedLocked(now time.Time) {
	var (
		soonest   netip.Addr
		soonestAt time.Time
	)
	for ip, until := range g.unlocked {
		if !until.After(now) {
			delete(g.unlocked, ip)
			continue
		}
		if soonestAt.IsZero() || until.Before(soonestAt) {
			soonest, soonestAt = ip, until
		}
	}
	if len(g.unlocked) >= maxUnlocked {
		delete(g.unlocked, soonest)
	}
}

// sourceLocked returns ip's entry, creating it, or nil when the table is full of
// sources that still matter - a source that goes untracked is simply not rate
// limited here, and the firewall in front still is.
func (g *Gate) sourceLocked(ip netip.Addr, now time.Time) *source {
	s := g.sources[ip]
	if s == nil {
		if len(g.sources) >= maxTracked {
			for k, e := range g.sources {
				if !e.bannedUntil.After(now) && now.Sub(e.lastSeen) > pruneIdle {
					delete(g.sources, k)
				}
			}
			if len(g.sources) >= maxTracked {
				return nil
			}
		}
		s = &source{}
		g.sources[ip] = s
	}
	s.lastSeen = now
	return s
}

// keyMatches compares in constant time, over hashes so that not even the
// key's length leaks.
func (g *Gate) keyMatches(k string) bool {
	sum := sha256.Sum256([]byte(k))
	return subtle.ConstantTimeCompare(sum[:], g.keySum[:]) == 1
}

// cookieValue is "<unix expiry>.<mac>": good for this proxy and key until the
// expiry, and needing nothing stored on frps.
func (g *Gate) cookieValue(expiry time.Time) string {
	exp := strconv.FormatInt(expiry.Unix(), 10)
	return exp + "." + g.cookieMAC(exp)
}

func (g *Gate) cookieMAC(exp string) string {
	m := hmac.New(sha256.New, g.cookieKey)
	m.Write([]byte(exp))
	return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}

func (g *Gate) cookieValid(v string) bool {
	exp, mac, ok := strings.Cut(v, ".")
	if !ok {
		return false
	}
	unix, err := strconv.ParseInt(exp, 10, 64)
	if err != nil || !time.Unix(unix, 0).After(g.now()) {
		return false
	}
	return hmac.Equal([]byte(mac), []byte(g.cookieMAC(exp)))
}

func orDefault(v, def int) int {
	if v <= 0 {
		return def
	}
	return v
}

// threshold reads an anti-spam limit: 0 is the default and a negative value
// switches the check off, returned as 0.
func threshold(v, def int) int {
	switch {
	case v == 0:
		return def
	case v < 0:
		return 0
	}
	return v
}

func seconds(n int) time.Duration {
	return time.Duration(n) * time.Second
}

func parsePrefixes(entries []string) ([]netip.Prefix, error) {
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
			return nil, fmt.Errorf("%q is not an IP or CIDR", e)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// addrOf extracts the source IP from an address with or without a port.
func addrOf(remoteAddr string) (netip.Addr, bool) {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	a, err := netip.ParseAddr(host)
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
