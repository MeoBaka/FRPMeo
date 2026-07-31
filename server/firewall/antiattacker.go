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
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// AntiAttacker is per-source rate limiting for traffic that already passed the
// rules and the reputation provider. Rules answer "is this peer allowed here",
// which is a question about identity; this answers "is it asking too often",
// which is a question about behavior, and no list of addresses can express it.
//
// It cannot stop packets: by the time frps is handed a connection the kernel has
// already completed the TCP handshake. What it does is make the refusal cost
// close to nothing - one map lookup - and, on the TCP side, close with RST so no
// socket lingers afterwards. Dropping traffic before the handshake needs the
// host firewall, which frps deliberately does not touch.
//
// Defaults come from XCord's anti-bot configuration, which has the advantage of
// being tuned against real attacks rather than guessed: a 5 s window, 4 attempts
// in it, banned after 3 separate windows go over, ban lasting 60 s.
type AntiAttackerConfig struct {
	// Enabled is off by default and deliberately so. A rate limit set too low
	// locks out real users, and unlike a deny rule nobody typed it in against a
	// specific address - it just starts refusing people.
	Enabled bool `json:"enabled"`

	// Scope is "all" (every proxy) or "selected" (only those named in Proxies).
	// Empty means "all".
	Scope string `json:"scope"`

	// Proxies lists the proxies this applies to when Scope is "selected", each
	// as "user/name", or bare "name" for proxies registered without a user.
	//
	// Named rather than addressed by port because http and https proxies all
	// answer on the one shared vhost port: a port cannot tell them apart, and
	// that is exactly where per-proxy limits are most wanted.
	Proxies []string `json:"proxies,omitempty"`

	// TCP counts connections and is consulted once per accepted connection.
	TCP RateProfile `json:"tcp"`

	// HTTP counts requests, not connections: the vhost reverse proxy pools work
	// connections by route, so a browser's second request usually arrives on a
	// connection that was admitted long ago.
	HTTP HTTPProfile `json:"http"`

	// UDP covers the udp and pe (Minecraft Bedrock) proxies and the udp half of
	// tcp+udp. Shaped differently from the other two, for reasons in UDPProfile.
	UDP UDPProfile `json:"udp"`

	// Control rate-limits the frps control port, and has its own profile rather
	// than sharing TCP's for a reason worth knowing before turning it on: an
	// frpc client's *work* connections arrive on that same port, so what looks
	// like one client is poolCount connections at startup and more as the pool
	// is replenished. Limits sized for logins would throttle a healthy client.
	//
	// Its own switch as well, matching how the rules half of this firewall
	// treats the control port: locking out the clients that keep the tunnels up
	// is a bigger mistake than letting one flood through, so nobody gets it
	// without asking.
	Control ControlProfile `json:"control"`

	// Web rate-limits the dashboard port, and SSH the ssh tunnel gateway port.
	//
	// Both are separate from Control rather than folded into it, even though the
	// rules half of this firewall does group the control port and the ssh
	// gateway under one switch. Grouping is right for allow and deny, which ask
	// who the peer is; it is wrong here, because these three carry very
	// different volumes. Only the control port has an frpc pool behind it, so
	// only it needs a limit in the hundreds - handing the same number to a login
	// form would leave a password guesser almost unhindered.
	Web ControlProfile `json:"web"`
	SSH ControlProfile `json:"ssh"`
}

// ControlProfile is the TCP shape again, plus the switch that arms it.
type ControlProfile struct {
	RateProfile

	// Enabled on RateProfile turns the counting on; this says the control port
	// is in scope at all. Both are needed, so enabling AntiAttacker for proxies
	// never quietly starts refusing frpc clients.
	Protect bool `json:"protect"`
}

// UDPProfile rate-limits UDP by packets and bytes, and deliberately cannot ban.
//
// UDP has no handshake, so the source address on a packet is whatever the
// sender wrote there. Three things follow, and each one rules out part of what
// the TCP profile does:
//
//   - Banning a source would be a weapon pointed at users. An attacker who
//     wants a particular address blocked only has to send bad traffic claiming
//     to be it. So there is no ban here at all, only a rate.
//   - Per-source counting is evadable by writing a new source on every packet,
//     which also floods the tracker table. That is what the global limits are
//     for: they are the only ones an attacker cannot sidestep by lying about
//     who they are.
//   - The unit is packets and bytes, not connections. A game client sends
//     hundreds of packets a second quite normally, so the TCP numbers would cut
//     off every real player immediately.
//
// A refused packet is dropped in silence. UDP has no way to say no.
type UDPProfile struct {
	Enabled bool `json:"enabled"`
	// WindowMs is the counting window, 1000 by default so the limits below read
	// as per-second rates.
	WindowMs int `json:"windowMs"`

	// Per-source ceilings. Zero means that dimension is not limited.
	MaxPacketsPerWindow int `json:"maxPacketsPerWindow"`
	MaxBytesPerWindow   int `json:"maxBytesPerWindow"`

	// Whole-listener ceilings, counted across every source together. Zero - the
	// default - means no global cap, because the right number is however much
	// traffic the host can carry and no default can guess it.
	//
	// Worth being plain about the trade: once a global cap is reached everything
	// is dropped, real traffic included. It bounds the damage rather than
	// sorting the good from the bad, and against spoofed sources that is the
	// only thing left that works.
	GlobalMaxPacketsPerWindow int `json:"globalMaxPacketsPerWindow"`
	GlobalMaxBytesPerWindow   int `json:"globalMaxBytesPerWindow"`

	IdleForgetMs int `json:"idleForgetMs"`
	MaxTracked   int `json:"maxTracked,omitempty"`
}

// RateProfile is one sliding window plus the escalation to a ban.
type RateProfile struct {
	Enabled bool `json:"enabled"`
	// WindowMs is how long one counting window lasts.
	WindowMs int `json:"windowMs"`
	// MaxPerWindow is how many attempts fit in a window before the rest are
	// refused.
	MaxPerWindow int `json:"maxPerWindow"`
	// BanViolations is how many *windows* have to go over before the source is
	// banned. Counted per window rather than per attempt on purpose: a single
	// burst is what a page load or a reconnect looks like, and banning on it
	// would catch mostly real users. Repeating the burst window after window is
	// what an attacker does.
	BanViolations int `json:"banViolations"`
	// BanSeconds is how long a ban lasts. It is never extended by further
	// attempts - see admit.
	BanSeconds int `json:"banSeconds"`
	// IdleForgetMs is how long a quiet source keeps its counters. It doubles as
	// the decay for violations: without it, one bad window a day would
	// eventually add up to a ban.
	IdleForgetMs int `json:"idleForgetMs"`
	// MaxTracked caps how many sources are remembered at once.
	MaxTracked int `json:"maxTracked,omitempty"`
}

// HTTPProfile adds what only makes sense once there are requests and headers.
type HTTPProfile struct {
	RateProfile

	// TrustedProxies are the peers whose X-Forwarded-For may be believed, as
	// IPs or CIDRs. Empty - the default - means the header is ignored and the
	// socket address is counted.
	//
	// The header is written by whoever is talking to us, so trusting it without
	// this list does not merely weaken the limit, it removes it: an attacker
	// sends a different value each request and is never the same source twice.
	TrustedProxies []string `json:"trustedProxies,omitempty"`

	// RetryAfterSec is the Retry-After sent with 429. Zero uses the remaining
	// ban or window, which is what a client actually needs to wait.
	RetryAfterSec int `json:"retryAfterSec,omitempty"`
}

// Defaults for the two profiles. The TCP numbers are XCord's speedy-login
// settings unchanged: an frps control port and an ssh tunnel see the same shape
// of traffic as a game login - a few attempts from one address, rarely.
//
// The HTTP numbers are not from XCord and are not tuned against anything; they
// are a starting point sized so an ordinary page load cannot trip them. A
// browser opens around six connections per origin and a single page can pull
// dozens of requests, so anything near the TCP figures would refuse real
// visitors on their first click.
func defaultTCPProfile() RateProfile {
	return RateProfile{
		WindowMs:      5000,
		MaxPerWindow:  4,
		BanViolations: 3,
		BanSeconds:    60,
		IdleForgetMs:  40000,
		MaxTracked:    65536,
	}
}

func defaultHTTPProfile() HTTPProfile {
	return HTTPProfile{
		RateProfile: RateProfile{
			WindowMs:      10000,
			MaxPerWindow:  120,
			BanViolations: 5,
			BanSeconds:    120,
			IdleForgetMs:  60000,
			MaxTracked:    65536,
		},
	}
}

// defaultControlProfile is far more permissive than the TCP one, and not from
// XCord - nothing there has an equivalent. The number has to cover an frpc
// client's pool: one login plus poolCount work connections at startup, then a
// replenishment for every connection a visitor consumes. 200 per 5 s leaves
// room for a busy client while still being orders of magnitude below a flood.
//
// Read the ban as what it is: a client that trips this stops reconnecting for a
// minute, and its tunnels are down for that minute. Raise it rather than trim
// it if there is any doubt.
func defaultControlProfile() RateProfile {
	return RateProfile{
		WindowMs:      5000,
		MaxPerWindow:  200,
		BanViolations: 3,
		BanSeconds:    60,
		IdleForgetMs:  40000,
		MaxTracked:    65536,
	}
}

// defaultWebProfile guards the dashboard, where the traffic is a person logging
// in rather than a client pool. The window still has to fit a page load: the
// dashboard is a single-page app, and a browser opens several connections for
// its assets before anyone has typed anything. 60 per 5 s leaves room for that
// and still cuts a password guesser down to a crawl.
//
// The ban is long on purpose. Nothing legitimate trips this, so the cost of a
// five-minute lockout falls almost entirely on whoever is guessing.
func defaultWebProfile() RateProfile {
	return RateProfile{
		WindowMs:      5000,
		MaxPerWindow:  60,
		BanViolations: 3,
		BanSeconds:    300,
		IdleForgetMs:  60000,
		MaxTracked:    65536,
	}
}

// defaultSSHProfile guards the ssh tunnel gateway. One client is one ssh
// session there - the tunneled data travels over an internal listener, not
// this port - so the limit can be far tighter than the control port's.
func defaultSSHProfile() RateProfile {
	return RateProfile{
		WindowMs:      5000,
		MaxPerWindow:  10,
		BanViolations: 3,
		BanSeconds:    300,
		IdleForgetMs:  60000,
		MaxTracked:    65536,
	}
}

// defaultUDPProfile takes its per-source rates from XCord's during-login
// anti-ddos settings (500 packets/s, 50000 bytes/s), which is the closest thing
// to a figure tested against real traffic. The global caps stay at zero: see
// UDPProfile on why no default can be right for them.
func defaultUDPProfile() UDPProfile {
	return UDPProfile{
		WindowMs:            1000,
		MaxPacketsPerWindow: 500,
		MaxBytesPerWindow:   50000,
		IdleForgetMs:        30000,
		MaxTracked:          65536,
	}
}

// normalize fills in zero fields with the defaults, leaving the ceilings alone:
// a zero there means "do not limit this dimension" and is a real choice.
func (p UDPProfile) normalize(def UDPProfile) UDPProfile {
	if p.WindowMs <= 0 {
		p.WindowMs = def.WindowMs
	}
	if p.IdleForgetMs <= 0 {
		p.IdleForgetMs = def.IdleForgetMs
	}
	if p.MaxTracked <= 0 {
		p.MaxTracked = def.MaxTracked
	}
	if p.IdleForgetMs < p.WindowMs {
		p.IdleForgetMs = p.WindowMs
	}
	return p
}

// normalize fills in zero fields with the defaults and clamps the rest into a
// range that can actually work. A window of 0 ms or a limit of 0 would refuse
// every request including the first, which is never what someone meant to type.
func (p RateProfile) normalize(def RateProfile) RateProfile {
	if p.WindowMs <= 0 {
		p.WindowMs = def.WindowMs
	}
	if p.MaxPerWindow <= 0 {
		p.MaxPerWindow = def.MaxPerWindow
	}
	if p.BanViolations <= 0 {
		p.BanViolations = def.BanViolations
	}
	if p.BanSeconds <= 0 {
		p.BanSeconds = def.BanSeconds
	}
	if p.IdleForgetMs <= 0 {
		p.IdleForgetMs = def.IdleForgetMs
	}
	if p.MaxTracked <= 0 {
		p.MaxTracked = def.MaxTracked
	}
	// A source has to be forgotten no sooner than the window it is being
	// counted in, or its count resets mid-window and the limit never bites.
	if p.IdleForgetMs < p.WindowMs {
		p.IdleForgetMs = p.WindowMs
	}
	return p
}

func (c AntiAttackerConfig) normalize() AntiAttackerConfig {
	scope := strings.ToLower(strings.TrimSpace(c.Scope))
	if scope != "selected" {
		scope = "all"
	}
	c.Scope = scope
	c.TCP = c.TCP.normalize(defaultTCPProfile())
	c.HTTP.RateProfile = c.HTTP.normalize(defaultHTTPProfile().RateProfile)
	c.UDP = c.UDP.normalize(defaultUDPProfile())
	c.Control.RateProfile = c.Control.normalize(defaultControlProfile())
	c.Web.RateProfile = c.Web.normalize(defaultWebProfile())
	c.SSH.RateProfile = c.SSH.normalize(defaultSSHProfile())
	proxies := make([]string, 0, len(c.Proxies))
	for _, p := range c.Proxies {
		if p = strings.TrimSpace(p); p != "" {
			proxies = append(proxies, p)
		}
	}
	c.Proxies = proxies
	return c
}

// appliesTo reports whether the given proxy is in scope. user may be empty for
// proxies registered without one.
//
// Matching on user+name rather than name alone: proxy names are only unique
// within a user, so keying on the name would hand one tenant's limits to
// another tenant who happened to pick the same name. A bare "name" entry still
// matches, so single-user setups need not spell out an empty user.
func (c AntiAttackerConfig) appliesTo(user, name string) bool {
	if c.Scope != "selected" {
		return true
	}
	qualified := name
	if user != "" {
		qualified = user + "/" + name
	}
	for _, p := range c.Proxies {
		if p == qualified || (user == "" && p == name) {
			return true
		}
	}
	return false
}

// ValidateAntiAttacker reports what is wrong with a submitted config, so the
// API can refuse it instead of storing something that quietly does nothing.
//
// Only the trusted proxy list can be wrong in a way worth rejecting: every
// numeric field has a sane fallback in normalize, but an address that does not
// parse is dropped, and a trusted list that silently lost an entry means
// X-Forwarded-For stops being believed without anyone being told.
func ValidateAntiAttacker(c AntiAttackerConfig) error {
	for _, e := range c.HTTP.TrustedProxies {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if _, err := netip.ParsePrefix(e); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(e); err != nil {
			return fmt.Errorf("trustedProxies: %q is not an IP or CIDR", e)
		}
	}
	return nil
}

// Verdict is the answer for one attempt.
type Verdict struct {
	// Allowed is false when the attempt should be refused.
	Allowed bool
	// Banned distinguishes "this source is serving a ban" from "this particular
	// attempt overflowed the window". Callers log them differently, and the http
	// side sends a longer Retry-After for the first.
	Banned bool
	// RetryAfter is how long until the source could succeed: the rest of the ban,
	// or the rest of the current window. Zero when allowed.
	RetryAfter time.Duration
	// Reason is never empty for a refusal - it goes straight into a log line.
	Reason string
}

var verdictAllow = Verdict{Allowed: true}

// tracker is what is remembered per source.
type tracker struct {
	windowStart int64 // ms
	count       int
	// violated records that this window has already contributed its one
	// violation, so a thousand attempts inside it still count once.
	violated    bool
	violations  int
	bannedUntil int64 // ms, 0 = not banned
	lastSeen    int64 // ms
}

// limiter holds the live per-source state for one profile.
type limiter struct {
	mu       sync.Mutex
	trackers map[string]*tracker
	nowMs    func() int64
}

func newLimiter(nowMs func() int64) *limiter {
	if nowMs == nil {
		nowMs = func() int64 { return time.Now().UnixMilli() }
	}
	return &limiter{trackers: make(map[string]*tracker), nowMs: nowMs}
}

// admit records one attempt from key and says whether it may proceed.
//
// The rule that matters most here is that a refusal never makes things worse
// for the source. A banned source is turned away without its counters being
// touched and without the ban being pushed back, because the obvious
// alternative - counting every attempt, ban included - means a client that
// retries every second holds itself in the ban forever, and a client that
// retries is exactly what a browser or a reconnecting tunnel is.
func (l *limiter) admit(key string, p RateProfile) Verdict {
	if !p.Enabled || key == "" {
		return verdictAllow
	}
	now := l.nowMs()

	l.mu.Lock()
	defer l.mu.Unlock()

	t := l.trackers[key]
	if t == nil {
		// Refuse to grow without bound. Pruning first usually makes room; when
		// it does not, the sources already being tracked keep being enforced
		// and new ones are let through. Losing the limit for new sources is the
		// lesser failure - a flood from more than MaxTracked distinct addresses
		// is distributed enough that per-source counting was never going to
		// stop it, and that is what the reputation provider is for.
		if len(l.trackers) >= p.MaxTracked {
			l.pruneLocked(now, p.IdleForgetMs)
			if len(l.trackers) >= p.MaxTracked {
				return verdictAllow
			}
		}
		t = &tracker{}
		l.trackers[key] = t
	}

	// Serving a ban: turn away, change nothing.
	if t.bannedUntil > now {
		t.lastSeen = now
		return Verdict{
			Banned:     true,
			RetryAfter: time.Duration(t.bannedUntil-now) * time.Millisecond,
			Reason:     "rate limit (banned)",
		}
	}

	idle := t.lastSeen != 0 && now-t.lastSeen > int64(p.IdleForgetMs)
	t.lastSeen = now

	// A ban that has run out, or a source that went quiet long enough, starts
	// over with a clean slate. Without the second case a source that misbehaves
	// once a week would eventually accumulate its way to a ban.
	if t.bannedUntil != 0 || idle {
		*t = tracker{lastSeen: now}
	}

	if now-t.windowStart >= int64(p.WindowMs) {
		t.windowStart = now
		t.count = 0
		t.violated = false
	}

	t.count++
	if t.count <= p.MaxPerWindow {
		return verdictAllow
	}

	if !t.violated {
		t.violated = true
		t.violations++
		if t.violations >= p.BanViolations {
			t.bannedUntil = now + int64(p.BanSeconds)*1000
			t.violations = 0
			return Verdict{
				Banned:     true,
				RetryAfter: time.Duration(p.BanSeconds) * time.Second,
				Reason:     "rate limit (banned)",
			}
		}
	}
	left := max(int64(p.WindowMs)-(now-t.windowStart), 0)
	return Verdict{
		RetryAfter: time.Duration(left) * time.Millisecond,
		Reason:     "rate limit",
	}
}

// pruneLocked drops sources that have been quiet for longer than idleMs and are
// not serving a ban.
func (l *limiter) pruneLocked(now int64, idleMs int) {
	for k, t := range l.trackers {
		if t.bannedUntil > now {
			continue
		}
		if now-t.lastSeen > int64(idleMs) {
			delete(l.trackers, k)
		}
	}
}

func (l *limiter) reset() {
	l.mu.Lock()
	l.trackers = make(map[string]*tracker)
	l.mu.Unlock()
}

// size reports how many sources are tracked. Used by tests and the dashboard.
func (l *limiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.trackers)
}

// udpTracker counts one window's worth of traffic, per source or globally.
type udpTracker struct {
	windowStart int64 // ms
	packets     int
	bytes       int
	lastSeen    int64 // ms
}

// roll starts a new window if the current one has run out.
func (t *udpTracker) roll(now int64, windowMs int) {
	if now-t.windowStart >= int64(windowMs) {
		t.windowStart = now
		t.packets = 0
		t.bytes = 0
	}
}

// over reports whether adding this packet would breach either ceiling. A zero
// ceiling means that dimension is not limited.
func (t *udpTracker) over(size, maxPackets, maxBytes int) bool {
	if maxPackets > 0 && t.packets+1 > maxPackets {
		return true
	}
	return maxBytes > 0 && t.bytes+size > maxBytes
}

// udpLimiter is the UDP counterpart of limiter: two dimensions, a global tier,
// and no ban.
type udpLimiter struct {
	mu       sync.Mutex
	trackers map[string]*udpTracker
	global   udpTracker
	nowMs    func() int64
}

func newUDPLimiter(nowMs func() int64) *udpLimiter {
	if nowMs == nil {
		nowMs = func() int64 { return time.Now().UnixMilli() }
	}
	return &udpLimiter{trackers: make(map[string]*udpTracker), nowMs: nowMs}
}

// admit records one packet of size bytes from key and says whether to forward
// it. Runs for every packet, so it does no allocation and takes one lock.
//
// The global tier is checked first, and on purpose: it is the tier that still
// means something when the source address is forged, and checking it first also
// means a flood of spoofed sources is turned away before it can create a
// tracker each.
func (l *udpLimiter) admit(key string, size int, p UDPProfile) bool {
	if !p.Enabled {
		return true
	}
	now := l.nowMs()

	l.mu.Lock()
	defer l.mu.Unlock()

	if p.GlobalMaxPacketsPerWindow > 0 || p.GlobalMaxBytesPerWindow > 0 {
		l.global.roll(now, p.WindowMs)
		if l.global.over(size, p.GlobalMaxPacketsPerWindow, p.GlobalMaxBytesPerWindow) {
			return false
		}
		l.global.packets++
		l.global.bytes += size
	}

	// With no per-source ceiling there is nothing left to count and no reason
	// to remember the source at all.
	if p.MaxPacketsPerWindow <= 0 && p.MaxBytesPerWindow <= 0 {
		return true
	}
	if key == "" {
		return true
	}

	t := l.trackers[key]
	if t == nil {
		if len(l.trackers) >= p.MaxTracked {
			l.pruneLocked(now, p.IdleForgetMs)
			if len(l.trackers) >= p.MaxTracked {
				// Table full of sources that are all still active. Forged
				// senders reach this quickly, which is exactly why the global
				// tier above exists and why this one gives up rather than
				// pretending to help.
				return true
			}
		}
		t = &udpTracker{windowStart: now}
		l.trackers[key] = t
	}
	t.lastSeen = now
	t.roll(now, p.WindowMs)

	if t.over(size, p.MaxPacketsPerWindow, p.MaxBytesPerWindow) {
		return false
	}
	t.packets++
	t.bytes += size
	return true
}

func (l *udpLimiter) pruneLocked(now int64, idleMs int) {
	for k, t := range l.trackers {
		if now-t.lastSeen > int64(idleMs) {
			delete(l.trackers, k)
		}
	}
}

func (l *udpLimiter) reset() {
	l.mu.Lock()
	l.trackers = make(map[string]*udpTracker)
	l.global = udpTracker{}
	l.mu.Unlock()
}

func (l *udpLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.trackers)
}

// clientKey picks what to count a request against: the socket address, or the
// first X-Forwarded-For entry when the socket address is a trusted proxy.
//
// xff is the raw header value; peer is the socket address, with or without a
// port. Returns the socket IP whenever the header cannot be believed, so a
// misconfigured trusted list fails towards counting too coarsely rather than
// not counting at all.
func clientKey(peer, xff string, trusted []netip.Prefix) string {
	ip := parseAddr(peer)
	if !ip.IsValid() {
		return ""
	}
	if xff == "" || len(trusted) == 0 || !prefixesContain(trusted, ip) {
		return ip.String()
	}
	// Left-most entry is the original client. Everything after it was added by
	// the hops in between, which we are not vouching for.
	first, _, _ := strings.Cut(xff, ",")
	fwd, err := netip.ParseAddr(strings.TrimSpace(first))
	if err != nil {
		return ip.String()
	}
	return fwd.Unmap().String()
}

func prefixesContain(prefixes []netip.Prefix, ip netip.Addr) bool {
	for _, p := range prefixes {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// compileTrusted turns the configured trusted proxies into prefixes once, at
// config time, rather than parsing strings per request. A bare address becomes
// a single-host prefix.
func compileTrusted(entries []string) []netip.Prefix {
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
		if a, err := netip.ParseAddr(e); err == nil {
			a = a.Unmap()
			out = append(out, netip.PrefixFrom(a, a.BitLen()))
		}
	}
	return out
}
