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
// opening a link, at a sign-in prompt, in an HTTP request, or on the first line
// of a connection - and frps forwards nothing to the backend for anyone who has
// not.
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
	"slices"
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
	// creds are the title/key pairs that open the proxy, and titles the
	// distinct titles among them in the order they came.
	creds  []credential
	titles []string

	// The ways the key may be presented, narrowed to what the proxy type can
	// carry.
	link, basic, header, form, json, bearer, line bool

	// rawPort is set for tcp and tcp+udp, where the backend may well be a
	// website the visitor came for. The unlocked page links back to it, and a
	// TLS request is answered over frps' own TLS so that a visitor who typed
	// https:// can still sign in. Elsewhere the page they asked for is not on
	// this port, or TLS has a better way in: https proxies are unlocked over
	// frps' http port.
	rawPort bool

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

// credential is one title/key pair, with the key kept as a hash.
type credential struct {
	title  string
	keySum [sha256.Size]byte
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
	var (
		creds  []credential
		titles []string
		keys   []string
	)
	for _, c := range cfg.AllCredentials() {
		creds = append(creds, credential{title: c.Title, keySum: sha256.Sum256([]byte(c.Key))})
		if !slices.ContainsFunc(titles, func(t string) bool { return strings.EqualFold(t, c.Title) }) {
			titles = append(titles, c.Title)
		}
		keys = append(keys, c.Key)
	}
	// Tied to the proxy and its keys: changing any of them logs every browser
	// out. Sorted, so reordering the logins changes nothing.
	slices.Sort(keys)
	cookieKey := sha256.Sum256([]byte("frp-secure-cookie\x00" + name + "\x00" + strings.Join(keys, "\x00")))
	rawPort := proxyType == string(v1.ProxyTypeTCP) || proxyType == string(v1.ProxyTypeTCPUDP)
	return &Gate{
		creds:       creds,
		titles:      titles,
		link:        cfg.HasMethod(v1.SecureMethodLink),
		basic:       cfg.HasMethod(v1.SecureMethodBasic),
		header:      cfg.HasMethod(v1.SecureMethodHeader),
		form:        cfg.HasMethod(v1.SecureMethodForm),
		json:        cfg.HasMethod(v1.SecureMethodJSON),
		bearer:      cfg.HasMethod(v1.SecureMethodBearer),
		line:        cfg.HasMethod(v1.SecureMethodLine) && v1.SecureLineApplies(proxyType),
		rawPort:     rawPort,
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

// TakesRequests reports whether the key can arrive in an HTTP request - a link,
// a sign-in, or a request carrying it.
func (g *Gate) TakesRequests() bool {
	return g.link || g.basic || g.header || g.form || g.json || g.bearer
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
// limited, which beats a table that grows without bound.
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

// matches reports whether key belongs to a login with this title - to any
// login when title is empty, as for a bearer token, which carries none.
// Compared in constant time over hashes, so not even the key's length leaks,
// and against every login, so the time taken does not say which one matched.
func (g *Gate) matches(title, key string) bool {
	sum := sha256.Sum256([]byte(key))
	ok := 0
	for _, c := range g.creds {
		if title != "" && !strings.EqualFold(c.title, title) {
			continue
		}
		ok |= subtle.ConstantTimeCompare(sum[:], c.keySum[:])
	}
	return ok == 1
}

// titleOf returns the title name names, compared the way header names are.
func (g *Gate) titleOf(name string) (string, bool) {
	for _, t := range g.titles {
		if strings.EqualFold(t, name) {
			return t, true
		}
	}
	return "", false
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
