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

	// GraceSeconds suspends every check for a while after frps starts.
	//
	// A restart is a burst that frps causes itself: every frpc reconnects at
	// once, each opening a login and a pool of work connections. Without a
	// grace period the first thing a fresh server can do is ban the clients it
	// exists to serve, and the tunnels stay down until the ban expires.
	GraceSeconds int `json:"graceSeconds"`

	// Attack decides when the expensive, blunter measures are worth their cost.
	Attack AttackConfig `json:"attack"`

	// Trust exempts sources that have already behaved.
	Trust TrustConfig `json:"trust"`

	// Strikes acts on signals that are not about volume at all.
	Strikes StrikeConfig `json:"strikes"`
}

// AttackConfig is the switch the blunt measures hang off.
//
// Most of what follows costs something - a shorter timeout cuts off slow but
// honest clients, dropped logs hide detail - so none of it is on all the time.
// This decides when "all the time" has arrived.
type AttackConfig struct {
	Enabled bool `json:"enabled"`
	// ConnectionsPerSec is the rate, counted across every source together, at
	// which frps starts calling this an attack.
	ConnectionsPerSec int `json:"connectionsPerSec"`
	// CooldownSec is how long the rate has to stay below the threshold before
	// things go back to normal. Without it a flood pacing itself around the
	// line would flip the state back and forth continuously.
	CooldownSec int `json:"cooldownSec"`
	// InitialTimeoutMs replaces the handshake read timeout while under attack.
	// Zero leaves it alone.
	//
	// This is the cheapest slowloris defense there is: a peer that opens a
	// connection and says nothing holds a socket for the whole timeout, so
	// cutting ten seconds to two frees them five times faster. It is also the
	// most disruptive if left on permanently, which is why it lives here.
	InitialTimeoutMs int `json:"initialTimeoutMs"`
	// InitialBufferLimitBytes caps how much a peer may send before it has
	// finished identifying itself. Zero leaves it alone.
	//
	// Nothing legitimate needs much here: a TLS ClientHello runs to a few
	// hundred bytes and frp's own header is smaller, so a peer that has pushed
	// kilobytes without completing the handshake is not mid-negotiation, it is
	// spending our memory. The connection counters cannot see it - one
	// connection is one connection however many megabytes it carries - which
	// is what makes this a different measurement rather than a tighter one.
	//
	// Unlike the timeout beside it, this one is not gated on the attack state:
	// the ceiling is far enough above real traffic that leaving it armed costs
	// honest clients nothing.
	InitialBufferLimitBytes int `json:"initialBufferLimitBytes,omitempty"`
}

// TrustConfig exempts a source that has already proved itself.
//
// This is what makes a tight limit safe to set. Without it every threshold is a
// compromise between turning away real users and letting attackers through;
// with it, the people who actually use the tunnel stop being measured at all.
type TrustConfig struct {
	Enabled bool `json:"enabled"`
	// AfterMs is how long a single connection has to last, carrying real
	// traffic, before its source is trusted. Scans and floods do not hold a
	// connection open and do not send anything - that is what separates them.
	AfterMs int `json:"afterMs"`
	// MinBytes is how much that connection has to have carried. A connection
	// held open but silent is a slowloris, not a user.
	MinBytes int `json:"minBytes"`
	// ForSeconds is how long the exemption lasts.
	ForSeconds int `json:"forSeconds"`
	MaxTracked int `json:"maxTracked,omitempty"`
}

// StrikeConfig bans on signals that say something a rate never can.
//
// A rate limit answers "is this too much traffic". These answer "is this a
// client at all", and the answer is worth far more: a peer that speaks the
// wrong protocol on the control port is not an frpc having a bad day. One
// strike here is worth a hundred connections of counting.
type StrikeConfig struct {
	Enabled bool `json:"enabled"`
	// ProtocolFailures is how many times a peer may fail to speak frp's
	// protocol - a non-TLS connection to a TLS-only port, a login that does not
	// verify - before it is banned. Zero switches this off.
	ProtocolFailures int `json:"protocolFailures"`
	// EmptyConnections is how many times a peer may connect, carry almost
	// nothing and leave, before it is banned. Zero switches this off.
	//
	// This is what a port scanner looks like, and it is invisible to a rate
	// limit: six connections spread over sixteen hours is nothing to count, but
	// six connections that each moved fifty bytes is not somebody using a
	// service.
	EmptyConnections int `json:"emptyConnections"`
	// EmptyBytes is the size below which a finished connection counts as empty.
	EmptyBytes int `json:"emptyBytes"`
	// BanSeconds is how long a strike ban lasts. Longer than a rate-limit ban
	// by default: this fires on evidence, not on a threshold somebody guessed.
	BanSeconds int `json:"banSeconds"`
	// ForgetMs drops a source's strikes once it has been quiet this long, so a
	// single bad day never adds up over weeks.
	ForgetMs   int `json:"forgetMs"`
	MaxTracked int `json:"maxTracked,omitempty"`
}

// ControlProfile is the TCP shape again, plus the switch that arms it.
type ControlProfile struct {
	RateProfile

	// Protect is the only switch these three answer to, and the embedded
	// RateProfile.Enabled is kept equal to it by normalize.
	//
	// Two flags were one too many. A stored config carries Enabled=false until
	// something sets it, so a config that arrived with only Protect turned on
	// would have read as armed and done nothing - the switch says yes and
	// nothing happens, which is the failure mode worth designing out rather
	// than documenting.
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

	// SubnetMaxPerWindow counts every source in the same block together - /24
	// for IPv4, /48 for IPv6 - as a second limit alongside the per-source one.
	// Zero, the default, leaves the tier off.
	//
	// It exists because a botnet does not need one address twice. Rotating
	// through a /24 gives every address a single, entirely unremarkable
	// attempt, and per-source counting has nothing to see. The block is what
	// stays the same.
	//
	// Unlike the per-source tier this one only ever throttles: it never bans.
	// A /24 can be a carrier-grade NAT block with a whole town behind it, and
	// banning the one address an attacker used would take the town with it.
	// Blocking a range outright is what a deny rule is for - that way it is
	// something a person decided, not something a counter did.
	SubnetMaxPerWindow int `json:"subnetMaxPerWindow,omitempty"`

	// GlobalMaxPerWindow counts every source together, and is the last tier
	// that still means anything when an attack is spread widely enough that no
	// address and no block repeats. Zero leaves it off.
	//
	// Like the subnet tier it only throttles. Once it bites it is turning away
	// real traffic along with the rest - it bounds the damage rather than
	// telling good from bad, so the number wants to be near what the host can
	// actually carry, not near normal load.
	GlobalMaxPerWindow int `json:"globalMaxPerWindow,omitempty"`

	// MaxConcurrent caps how many connections one source may hold open at once.
	// Zero leaves it off.
	//
	// A different axis from everything above: the rate tiers count connections
	// being *made*, and a peer that opens a thousand and then goes quiet breaks
	// no rate at all. That is slowloris, and only a concurrency cap sees it.
	MaxConcurrent int `json:"maxConcurrent,omitempty"`
}

// HTTPProfile adds what only makes sense once there are requests and headers.
type HTTPProfile struct {
	RateProfile

	// Which peers' X-Forwarded-For may be believed is not configured here: it
	// is the allow rules marked trusted. See Rule.Trusted.
	//
	// The header is written by whoever is talking to us, so believing it from
	// the wrong peer does not merely weaken the limit, it removes it - an
	// attacker sends a different value each request and is never the same
	// source twice. That is why it is the trusted tick rather than any allow
	// rule: "allow" says a peer may pass, and a broad allow would hand the
	// header to everyone it covers.

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

// normalizeWith fills the numbers in and ties Enabled to Protect, so the one
// switch in the dashboard is the whole story.
func (p ControlProfile) normalizeWith(def RateProfile) ControlProfile {
	p.RateProfile = p.normalize(def)
	p.Enabled = p.Protect
	return p
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

// normalize fills in the zero fields with the defaults. The ceilings are left
// alone, because a zero there means "do not limit this dimension" and is a real
// choice - except when every one of them is zero, which would leave the profile
// switched on and limiting nothing. Nobody enables a rate limit to ask for no
// rate limit, so that case takes the per-source defaults; turning a dimension
// off is still available by setting the other one and leaving this at zero.
func (p UDPProfile) normalize(def UDPProfile) UDPProfile {
	if p.Enabled && p.MaxPacketsPerWindow <= 0 && p.MaxBytesPerWindow <= 0 &&
		p.GlobalMaxPacketsPerWindow <= 0 && p.GlobalMaxBytesPerWindow <= 0 {
		p.MaxPacketsPerWindow = def.MaxPacketsPerWindow
		p.MaxBytesPerWindow = def.MaxBytesPerWindow
	}
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

// Defaults for the three coordinating pieces.
//
// The attack threshold is XCord's anti-bot-activate-connections unchanged (40
// connections in a second), and the cooldown its anti-bot-deactivate-delay. The
// shortened timeout is its anti-hang force-timeout-time.
//
// The strike numbers are not from XCord - it has no equivalent, because a
// Minecraft server can tell a bot from a player by asking it questions and frps
// cannot. They are set low on purpose: unlike a rate, these fire on evidence
// that a peer is not a client at all, so there is little reason to be patient.
func defaultAttack() AttackConfig {
	// 64 KiB before a peer has said who it is. Two orders of magnitude above a
	// large ClientHello, so it never argues with a real client, and small
	// enough that a peer trying to make frps hold memory is cut off early.
	return AttackConfig{
		ConnectionsPerSec: 40, CooldownSec: 60, InitialTimeoutMs: 2000,
		InitialBufferLimitBytes: 65536,
	}
}

func defaultTrust() TrustConfig {
	// Five minutes of real use, XCord's time-to-whitelist, buying a day's
	// exemption. XCord grants thirty days; a day is the same idea with less to
	// regret if the address changes hands.
	return TrustConfig{AfterMs: 300000, MinBytes: 4096, ForSeconds: 86400, MaxTracked: 65536}
}

func defaultStrikes() StrikeConfig {
	return StrikeConfig{
		ProtocolFailures: 3,
		EmptyConnections: 6,
		EmptyBytes:       64,
		BanSeconds:       600,
		ForgetMs:         3600000,
		MaxTracked:       65536,
	}
}

func (c AttackConfig) normalize(def AttackConfig) AttackConfig {
	if c.ConnectionsPerSec <= 0 {
		c.ConnectionsPerSec = def.ConnectionsPerSec
	}
	if c.CooldownSec <= 0 {
		c.CooldownSec = def.CooldownSec
	}
	if c.InitialTimeoutMs < 0 {
		c.InitialTimeoutMs = 0
	}
	return c
}

func (c TrustConfig) normalize(def TrustConfig) TrustConfig {
	if c.AfterMs <= 0 {
		c.AfterMs = def.AfterMs
	}
	if c.MinBytes <= 0 {
		c.MinBytes = def.MinBytes
	}
	if c.ForSeconds <= 0 {
		c.ForSeconds = def.ForSeconds
	}
	if c.MaxTracked <= 0 {
		c.MaxTracked = def.MaxTracked
	}
	return c
}

func (c StrikeConfig) normalize(def StrikeConfig) StrikeConfig {
	if c.ProtocolFailures < 0 {
		c.ProtocolFailures = 0
	}
	if c.EmptyConnections < 0 {
		c.EmptyConnections = 0
	}
	// Both at zero with the group switched on would be a switch that does
	// nothing - the same trap the udp ceilings had.
	if c.Enabled && c.ProtocolFailures == 0 && c.EmptyConnections == 0 {
		c.ProtocolFailures = def.ProtocolFailures
		c.EmptyConnections = def.EmptyConnections
	}
	if c.EmptyBytes <= 0 {
		c.EmptyBytes = def.EmptyBytes
	}
	if c.BanSeconds <= 0 {
		c.BanSeconds = def.BanSeconds
	}
	if c.ForgetMs <= 0 {
		c.ForgetMs = def.ForgetMs
	}
	if c.MaxTracked <= 0 {
		c.MaxTracked = def.MaxTracked
	}
	return c
}

func (c AntiAttackerConfig) normalize() AntiAttackerConfig {
	c.TCP = c.TCP.normalize(defaultTCPProfile())
	c.HTTP.RateProfile = c.HTTP.normalize(defaultHTTPProfile().RateProfile)
	c.UDP = c.UDP.normalize(defaultUDPProfile())
	c.Control = c.Control.normalizeWith(defaultControlProfile())
	c.Web = c.Web.normalizeWith(defaultWebProfile())
	c.SSH = c.SSH.normalizeWith(defaultSSHProfile())
	c.Attack = c.Attack.normalize(defaultAttack())
	c.Trust = c.Trust.normalize(defaultTrust())
	c.Strikes = c.Strikes.normalize(defaultStrikes())
	if c.GraceSeconds < 0 {
		c.GraceSeconds = 0
	}
	return c
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
	// onBan is told about each ban so it can also be carried out outside this
	// process. Never called with the lock held: it may talk to the kernel.
	onBan func(key string, ttl time.Duration)
}

func newLimiter(nowMs func() int64) *limiter {
	if nowMs == nil {
		nowMs = func() int64 { return time.Now().UnixMilli() }
	}
	return &limiter{trackers: make(map[string]*tracker), nowMs: nowMs}
}

// onBan, when set, is told about every ban this ledger hands out, so it can be
// carried out somewhere else as well - see Firewall.noteBan. Set once at
// construction and never while admissions are running.
func (l *limiter) reportBansTo(fn func(key string, ttl time.Duration)) {
	l.onBan = fn
}

// admit records one attempt from key and says whether it may proceed.
//
// The rule that matters most here is that a refusal never makes things worse
// for the source. A banned source is turned away without its counters being
// touched and without the ban being pushed back, because the obvious
// alternative - counting every attempt, ban included - means a client that
// retries every second holds itself in the ban forever, and a client that
// retries is exactly what a browser or a reconnecting tunnel is.
//
// banning says whether a violation may escalate to a ban right now. With it
// false the source is still throttled and its violation still counted; only the
// step from counting to banning is withheld. See Firewall.banning.
func (l *limiter) admit(key string, p RateProfile, banning bool) Verdict {
	if !p.Enabled || key == "" {
		return verdictAllow
	}
	now := l.nowMs()

	// Registered before the unlock so it runs after it: onBan may talk to the
	// kernel, which is not something to do holding the ledger's lock.
	var banned time.Duration
	defer func() {
		if banned > 0 && l.onBan != nil {
			l.onBan(key, banned)
		}
	}()

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
		// Bans are handed out only while frps is actually under attack. A
		// server nobody is flooding has no business banning anyone: a client
		// that trips the window twice at three in the morning is a client
		// having a bad minute, not an attacker, and the throttle already dealt
		// with it. Violations still accumulate, so a source that keeps it up
		// into an attack is banned on the spot rather than starting over.
		if banning && t.violations >= p.BanViolations {
			t.bannedUntil = now + int64(p.BanSeconds)*1000
			t.violations = 0
			banned = time.Duration(p.BanSeconds) * time.Second
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

// attackState tracks the connection rate across every source and says whether
// frps is currently under attack.
//
// Counted in whole seconds rather than a sliding window: the number only has to
// be right enough to flip a switch, and a second of granularity keeps this to
// two integers on a path that every connection walks.
//
// The state is held as "when was the rate last over the line" rather than as a
// boolean, because a boolean can only change when something calls in, and the
// end of an attack is exactly when nothing does. A flood that stops dead leaves
// no connection behind to notice it stopped, so a flag set on the way up would
// stay up until the next client arrived - keeping the shortened handshake
// timeout in force against honest traffic for as long as the server was quiet.
// A timestamp compared against the clock has no such gap.
type attackState struct {
	mu     sync.Mutex
	nowMs  func() int64
	second int64 // unix second the count belongs to
	count  int

	// overAt is when a finished second was last judged to be at or above the
	// threshold. Zero means it never has been.
	overAt int64

	// cooldownMs is remembered from the last note so isUnder can answer
	// without being handed the config, which the callers that ask - a timeout,
	// a status page - do not have.
	cooldownMs int64
}

func newAttackState(nowMs func() int64) *attackState {
	if nowMs == nil {
		nowMs = func() int64 { return time.Now().UnixMilli() }
	}
	return &attackState{nowMs: nowMs}
}

// note records one connection towards the per-second rate. Whether the state is
// up is asked separately, through isUnder, because the answer matters at points
// that are not admitting a connection - shortening a timeout, drawing a status.
func (a *attackState) note(c AttackConfig) {
	if !c.Enabled || c.ConnectionsPerSec <= 0 {
		return
	}
	now := a.nowMs()
	sec := now / 1000

	a.mu.Lock()
	defer a.mu.Unlock()

	a.cooldownMs = int64(c.CooldownSec) * 1000

	if sec != a.second {
		// A second finished. Judge it, then start the next one.
		if a.count >= c.ConnectionsPerSec {
			a.overAt = now
		}
		a.second = sec
		a.count = 0
	}
	a.count++
}

// isUnder reports whether the attack state is up: the rate was over the line
// recently enough that the cooldown has not run out.
//
// Holding for the whole cooldown is what stops a flood pacing itself around the
// threshold from flipping the state back and forth.
func (a *attackState) isUnder() bool {
	a.mu.Lock()
	defer a.mu.Unlock()

	if a.overAt == 0 {
		return false
	}
	return a.nowMs()-a.overAt <= a.cooldownMs
}

func (a *attackState) reset() {
	a.mu.Lock()
	a.second, a.count, a.overAt, a.cooldownMs = 0, 0, 0, 0
	a.mu.Unlock()
}

// trustStore remembers sources that have already behaved.
type trustStore struct {
	mu    sync.Mutex
	until map[string]int64 // key -> ms
	nowMs func() int64
}

func newTrustStore(nowMs func() int64) *trustStore {
	if nowMs == nil {
		nowMs = func() int64 { return time.Now().UnixMilli() }
	}
	return &trustStore{until: make(map[string]int64), nowMs: nowMs}
}

// grant records that key has earned an exemption.
func (s *trustStore) grant(key string, c TrustConfig) {
	if !c.Enabled || key == "" {
		return
	}
	now := s.nowMs()

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.until) >= c.MaxTracked {
		for k, exp := range s.until {
			if exp <= now {
				delete(s.until, k)
			}
		}
		if len(s.until) >= c.MaxTracked {
			return
		}
	}
	s.until[key] = now + int64(c.ForSeconds)*1000
}

func (s *trustStore) trusted(key string, c TrustConfig) bool {
	if !c.Enabled || key == "" {
		return false
	}
	now := s.nowMs()

	s.mu.Lock()
	defer s.mu.Unlock()

	exp, ok := s.until[key]
	if !ok {
		return false
	}
	if exp <= now {
		delete(s.until, key)
		return false
	}
	return true
}

func (s *trustStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.until)
}

// strikeStore counts the signals that are about what a peer is rather than how
// much of it there is, and bans on them.
type strikeStore struct {
	mu      sync.Mutex
	entries map[string]*strikeEntry
	nowMs   func() int64
	onBan   func(key string, ttl time.Duration)
}

type strikeEntry struct {
	protocol    int
	empty       int
	lastSeen    int64
	bannedUntil int64
}

func newStrikeStore(nowMs func() int64) *strikeStore {
	if nowMs == nil {
		nowMs = func() int64 { return time.Now().UnixMilli() }
	}
	return &strikeStore{entries: make(map[string]*strikeEntry), nowMs: nowMs}
}

func (s *strikeStore) reportBansTo(fn func(key string, ttl time.Duration)) {
	s.onBan = fn
}

// strikeKind names which counter an event feeds.
type strikeKind int

const (
	strikeProtocol strikeKind = iota
	strikeEmpty
)

// add records one strike. Whether the source is now banned is asked through
// banned, on the admission path, rather than returned here: the callers that
// report a strike are handling a failure and have nothing to do with the
// answer.
func (s *strikeStore) add(key string, kind strikeKind, c StrikeConfig) {
	if !c.Enabled || key == "" {
		return
	}
	limit := c.ProtocolFailures
	if kind == strikeEmpty {
		limit = c.EmptyConnections
	}
	if limit <= 0 {
		return
	}
	now := s.nowMs()

	// Same ordering as limiter.admit: after the unlock, not during it.
	var banned time.Duration
	defer func() {
		if banned > 0 && s.onBan != nil {
			s.onBan(key, banned)
		}
	}()

	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.entries[key]
	if e == nil {
		if len(s.entries) >= c.MaxTracked {
			s.pruneLocked(now, c.ForgetMs)
			if len(s.entries) >= c.MaxTracked {
				return
			}
		}
		e = &strikeEntry{}
		s.entries[key] = e
	}
	// A source that has been quiet long enough starts clean, so one bad day
	// never accumulates into a ban weeks later.
	if e.lastSeen != 0 && now-e.lastSeen > int64(c.ForgetMs) && e.bannedUntil <= now {
		*e = strikeEntry{}
	}
	e.lastSeen = now

	if kind == strikeEmpty {
		e.empty++
		if e.empty >= limit {
			e.bannedUntil = now + int64(c.BanSeconds)*1000
			e.empty = 0
			banned = time.Duration(c.BanSeconds) * time.Second
		}
	} else {
		e.protocol++
		if e.protocol >= limit {
			e.bannedUntil = now + int64(c.BanSeconds)*1000
			e.protocol = 0
			banned = time.Duration(c.BanSeconds) * time.Second
		}
	}
}

// banned reports whether key is serving a strike ban. Like the rate limiter it
// does not extend the ban for asking.
func (s *strikeStore) banned(key string, c StrikeConfig) bool {
	if !c.Enabled || key == "" {
		return false
	}
	now := s.nowMs()

	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.entries[key]
	return e != nil && e.bannedUntil > now
}

// suspect reports whether key has strikes against it without having reached a
// ban.
//
// The middle of the ledger used to mean nothing: a source could fail the
// protocol twice out of three, or connect and carry nothing four times out of
// five, and be measured exactly like a source with a clean record. The evidence
// was there and went unused until the last strike landed.
//
// It is deliberately not a ban of its own. What it earns is a tighter budget -
// see halved - which turns a partial record into an earlier refusal rather than
// into a verdict the evidence does not yet support.
func (s *strikeStore) suspect(key string, c StrikeConfig) bool {
	if !c.Enabled || key == "" {
		return false
	}
	now := s.nowMs()

	s.mu.Lock()
	defer s.mu.Unlock()

	e := s.entries[key]
	if e == nil || e.bannedUntil > now {
		return false
	}
	// A record old enough to be forgotten is not held against anyone; add would
	// have cleared it on the next strike anyway.
	if e.lastSeen != 0 && now-e.lastSeen > int64(c.ForgetMs) {
		return false
	}
	return e.protocol > 0 || e.empty > 0
}

func (s *strikeStore) pruneLocked(now int64, forgetMs int) {
	for k, e := range s.entries {
		if e.bannedUntil > now {
			continue
		}
		if now-e.lastSeen > int64(forgetMs) {
			delete(s.entries, k)
		}
	}
}

func (s *strikeStore) size() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.entries)
}

func (s *strikeStore) reset() {
	s.mu.Lock()
	s.entries = make(map[string]*strikeEntry)
	s.mu.Unlock()
}

// concurrency counts connections a source currently holds open.
type concurrency struct {
	mu   sync.Mutex
	open map[string]int
}

func newConcurrency() *concurrency {
	return &concurrency{open: make(map[string]int)}
}

// acquire takes a slot, reporting false when the source is already at its cap.
func (c *concurrency) acquire(key string, limit int) bool {
	if limit <= 0 || key == "" {
		return true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.open[key] >= limit {
		return false
	}
	c.open[key]++
	return true
}

func (c *concurrency) release(key string) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if n := c.open[key]; n > 1 {
		c.open[key] = n - 1
	} else {
		delete(c.open, key)
	}
}

func (c *concurrency) size() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.open)
}

func (c *concurrency) reset() {
	c.mu.Lock()
	c.open = make(map[string]int)
	c.mu.Unlock()
}

// globalKey is the single bucket the whole-listener tier counts into. Prefixed
// like the subnet keys so it can never be an address.
const globalKey = "net:*"

// admitBoth runs the subnet tier and then the per-source one, and is what the
// Admit* methods call. key is the per-source key from clientKey.
//
// Subnet first, and its refusal returns before the per-source counter is
// touched: a source turned away for what its neighbors are doing has not made
// an attempt of its own, and counting it would push it towards a ban it did not
// earn.
func (l *limiter) admitBoth(key string, p RateProfile, banning bool) Verdict {
	// Widest tier first, narrowest last. Each one that refuses does so before
	// the narrower counters are touched, so a source turned away for the
	// company it keeps is not also pushed towards a ban of its own.
	if p.GlobalMaxPerWindow > 0 {
		gp := p
		gp.MaxPerWindow = p.GlobalMaxPerWindow
		gp.BanViolations = maxInt // throttle only, like the subnet tier
		if v := l.admit(globalKey, gp, banning); !v.Allowed {
			v.Reason = "rate limit (global)"
			return v
		}
	}
	if p.SubnetMaxPerWindow > 0 {
		if sk := subnetKey(key); sk != "" {
			sp := p
			sp.MaxPerWindow = p.SubnetMaxPerWindow
			// The subnet tier throttles and never bans - see
			// RateProfile.SubnetMaxPerWindow. A violation count it can never
			// reach is how that is expressed, so the escalation simply never
			// fires.
			sp.BanViolations = maxInt
			if v := l.admit(sk, sp, banning); !v.Allowed {
				v.Reason = "rate limit (subnet)"
				return v
			}
		}
	}
	return l.admit(key, p, banning)
}

const maxInt = int(^uint(0) >> 1)

// halved returns p with the per-source allowance and the violation count both
// cut in half, for a source the strike ledger has something on.
//
// Half rather than a ban, because that is what the evidence supports: a couple
// of failed protocol attempts say "watch this one", not "this one is an
// attack". It reaches the same ban sooner from both directions - fewer
// connections per window, fewer windows before the count is met - while a
// source that was simply having a bad minute still gets through.
//
// The wider tiers are left alone. They count everyone together, so halving them
// for one suspect source would throttle every neighbor it has.
func halved(p RateProfile) RateProfile {
	if p.MaxPerWindow > 1 {
		p.MaxPerWindow = (p.MaxPerWindow + 1) / 2
	}
	if p.BanViolations > 1 && p.BanViolations != maxInt {
		p.BanViolations = (p.BanViolations + 1) / 2
	}
	return p
}

// subnetKey maps a source key to the block it shares with its neighbors: /24
// for IPv4, /48 for IPv6. Returns "" when the key is not an address, which
// leaves the subnet tier out of the decision rather than guessing.
//
// The "net:" prefix keeps block keys and address keys apart in the one table -
// without it a /24 named "1.2.3.0/24" and an address could never collide, but
// the intent would rest on that being true forever.
func subnetKey(ipKey string) string {
	ip, err := netip.ParseAddr(ipKey)
	if err != nil {
		return ""
	}
	bits := 24
	if ip.Is6() && !ip.Is4In6() {
		bits = 48
	}
	p, err := ip.Prefix(bits)
	if err != nil {
		return ""
	}
	return "net:" + p.String()
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

// BanEntry is one source the firewall is currently turning away, as reported to
// the dashboard.
type BanEntry struct {
	Source string `json:"source"`
	// Tier names where the ban came from: which listener, or "strike" for the
	// signal-based ones.
	Tier string `json:"tier"`
	// Reason is the short label, e.g. "rate limit" or "not a client".
	Reason string `json:"reason"`
	// SecondsLeft is how long is left to serve.
	SecondsLeft int `json:"secondsLeft"`
}

// bans lists the sources currently serving a rate-limit ban in this limiter.
//
// Skips the aggregate buckets: a "net:" key is a block or the global counter,
// neither of which can be banned - both tiers only ever throttle - so anything
// with that prefix would be noise if it ever appeared.
func (l *limiter) bans(tier string, now int64) []BanEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	out := make([]BanEntry, 0, 8)
	for k, t := range l.trackers {
		if t.bannedUntil <= now || strings.HasPrefix(k, "net:") {
			continue
		}
		out = append(out, BanEntry{
			Source:      k,
			Tier:        tier,
			Reason:      "rate limit",
			SecondsLeft: int((t.bannedUntil - now + 999) / 1000),
		})
	}
	return out
}

func (s *strikeStore) bans(now int64) []BanEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]BanEntry, 0, 8)
	for k, e := range s.entries {
		if e.bannedUntil <= now {
			continue
		}
		out = append(out, BanEntry{
			Source:      k,
			Tier:        "strike",
			Reason:      "not a client",
			SecondsLeft: int((e.bannedUntil - now + 999) / 1000),
		})
	}
	return out
}

// Status is what the dashboard shows about the live state, as opposed to the
// settings. Counters alone would not answer the question people actually have,
// which is "who is being turned away and why" - so the bans are listed.
type Status struct {
	UnderAttack bool `json:"underAttack"`
	// InGrace is true while the post-startup window is still suppressing checks.
	// Worth reporting: otherwise a freshly restarted server looks like one whose
	// settings are not working.
	InGrace bool `json:"inGrace"`
	// Tracked is how many sources each layer is remembering, which is what
	// approaches MaxTracked when an attack is wide enough to matter.
	Tracked   map[string]int `json:"tracked"`
	Trusted   int            `json:"trusted"`
	OpenConns int            `json:"openConns"`
	Bans      []BanEntry     `json:"bans"`
}

// clientKey picks what to count a request against: the socket address, or the
// first X-Forwarded-For entry when the socket address is a trusted proxy.
//
// xff is the raw header value; peer is the socket address, with or without a
// port. Returns the socket IP whenever the header cannot be believed, so a
// misconfigured trusted list fails towards counting too coarsely rather than
// not counting at all.
func clientKey(peer, xff string, trusted func(netip.Addr) bool) string {
	ip := parseAddr(peer)
	if !ip.IsValid() {
		return ""
	}
	if xff == "" || trusted == nil || !trusted(ip) {
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
