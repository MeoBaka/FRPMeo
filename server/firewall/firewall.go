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

// Package firewall is the anti-bot layer for frps. It measures how a source
// behaves and turns away the ones that are not clients:
//
//   - per-source rate limits on each surface (proxy, control, dashboard, ssh,
//     udp), with a wider subnet tier behind them.
//   - strikes for evidence that is not about volume: a peer that cannot speak
//     the protocol, a string of connections that carried nothing.
//   - trust for a source that has already held a real connection, which is what
//     makes a tight limit safe to set.
//   - an attack state that arms the blunter measures only while the connection
//     rate says they are worth their cost.
//   - an optional kernel ban, so a source that keeps coming back stops reaching
//     frps at all.
//
// What this package deliberately does not do is decide who a peer is. There is
// no allow/deny list and no reputation lookup: neither survived contact with a
// real flood, because by the time either could run the connection had already
// been accepted and the cost already paid.
//
// Everything here runs after accept(), which bounds what it can achieve. It is
// not a defense against volumetric attacks - those never reach userspace - and
// nothing in it substitutes for filtering upstream of the host.
package firewall

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Config is the whole of what this package is told, and the whole of what it
// reports back.
type Config struct {
	// AntiAttacker is the rate limiting and everything hanging off it. Off by
	// default; see AntiAttackerConfig.
	AntiAttacker AntiAttackerConfig `json:"antiAttacker"`
	// KernelBan asks the host firewall to drop a banned source's packets. Off
	// by default; see KernelBanConfig.
	KernelBan KernelBanConfig `json:"kernelBan"`
}

// Firewall holds live state and persists it to a JSON file.
type Firewall struct {
	mu   sync.RWMutex
	path string

	// aa and its limiters are the rate-limiting half.
	aa          AntiAttackerConfig
	tcpLimiter  *limiter
	httpLimiter *limiter
	udpLimiter  *udpLimiter
	// ctlLimiter is kept apart from tcpLimiter on purpose. One frpc client is
	// both a control connection and a stream of work connections from the same
	// address, and it may also be reaching proxies from there; sharing a
	// counter would let one of those starve the other.
	ctlLimiter *limiter
	// webLimiter and sshLimiter are likewise their own: the dashboard, the ssh
	// gateway and the control port are three different doors, and someone
	// hammering one must not use up another's budget.
	webLimiter *limiter
	sshLimiter *limiter

	// The pieces that are not about counting attempts: attack state, the
	// exemption store, the strike counters and the concurrency ledger.
	attack    *attackState
	trust     *trustStore
	strikes   *strikeStore
	conc      *concurrency
	startedAt int64 // ms, for the grace period
	nowMsFn   func() int64

	// monitors aggregate what each surface decided, so a flood costs a line
	// every few seconds instead of one per connection.
	monitors map[Surface]*monitor

	// banCfg is kept verbatim so the config round-trips; banSink is the live
	// backend it selected, never nil once New has run.
	banCfg  KernelBanConfig
	banSink banSink
}

// New loads state from path.
func New(path string) (*Firewall, error) {
	f := &Firewall{
		path:        path,
		tcpLimiter:  newLimiter(nil),
		httpLimiter: newLimiter(nil),
		udpLimiter:  newUDPLimiter(nil),
		ctlLimiter:  newLimiter(nil),
		webLimiter:  newLimiter(nil),
		sshLimiter:  newLimiter(nil),
		attack:      newAttackState(nil),
		trust:       newTrustStore(nil),
		strikes:     newStrikeStore(nil),
		conc:        newConcurrency(),
		nowMsFn:     func() int64 { return time.Now().UnixMilli() },
		startedAt:   time.Now().UnixMilli(),
		monitors:    make(map[Surface]*monitor, len(surfaces)),
	}
	f.banSink = noopSink{}
	f.ctlLimiter.reportBansTo(f.noteBan)
	f.tcpLimiter.reportBansTo(f.noteBan)
	f.httpLimiter.reportBansTo(f.noteBan)
	f.webLimiter.reportBansTo(f.noteBan)
	f.sshLimiter.reportBansTo(f.noteBan)
	f.strikes.reportBansTo(f.noteBan)
	for _, s := range surfaces {
		f.monitors[s] = newMonitor(string(s))
	}

	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		var c Config
		if err := json.Unmarshal(b, &c); err != nil {
			return nil, err
		}
		f.aa = c.AntiAttacker
		f.banCfg = c.KernelBan
	case os.IsNotExist(err):
	default:
		return nil, err
	}

	f.mu.Lock()
	f.applyAntiAttackerLocked(f.aa)
	f.banSink = newBanSink(f.banCfg)
	_ = f.saveLocked()
	f.mu.Unlock()

	go f.reportSurfaces()
	return f, nil
}

// Snapshot returns the current state for the dashboard.
func (f *Firewall) Snapshot() Config {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return Config{AntiAttacker: f.aa, KernelBan: f.banCfg}
}

// SetConfig replaces the whole configuration.
func (f *Firewall) SetConfig(c Config) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.applyAntiAttackerLocked(c.AntiAttacker)
	f.applyKernelBanLocked(c.KernelBan)
	return f.saveLocked()
}

// applyAntiAttackerLocked stores a normalized config. Counters are dropped
// whenever the settings change: they were
// accumulated against different thresholds, and keeping them could hold someone
// in a ban that the new settings would never have handed out.
func (f *Firewall) applyAntiAttackerLocked(c AntiAttackerConfig) {
	f.aa = c.normalize()
	f.tcpLimiter.reset()
	f.httpLimiter.reset()
	f.udpLimiter.reset()
	f.ctlLimiter.reset()
	f.webLimiter.reset()
	f.sshLimiter.reset()
	f.attack.reset()
	f.conc.reset()
	// Trust and strikes survive a config change on purpose. Both are records of
	// what a source actually did, not counters accumulated against a threshold
	// that just moved - throwing them away would re-measure people who had
	// already earned their exemption, and forgive peers caught red-handed.
}

// inGrace reports whether frps is still inside the window after startup where
// no check applies. Called with no lock held; startedAt never changes.
func (f *Firewall) inGrace(grace int) bool {
	return grace > 0 && f.nowMsFn()-f.startedAt < int64(grace)*1000
}

// exempt gathers the three ways an admission decision can be skipped entirely,
// so every Admit* answers them the same way and in the same order.
//
// Grace first: a server that has just started has no business banning anybody,
// least of all the clients reconnecting to it. Then trust, which is a source
// that already proved itself. Only then is a strike ban consulted - it comes
// last of the three because unlike the others it is a refusal, not a pass.
func (f *Firewall) exempt(key string, c AntiAttackerConfig) (skip bool, refuse bool) {
	if f.inGrace(c.GraceSeconds) {
		return true, false
	}
	if f.trust.trusted(key, c.Trust) {
		return true, false
	}
	if f.strikes.banned(key, c.Strikes) {
		return false, true
	}
	return false, false
}

// profileFor applies the strike ledger's opinion of key to a rate profile.
//
// Three tiers on one code path, in order of what the source has shown us: an
// earned trust skips the counters entirely, a clean record is measured as
// configured, and a source with strikes short of a ban gets half the budget.
// The middle of the ledger used to mean nothing at all - the evidence sat there
// unused until the last strike landed.
func (f *Firewall) profileFor(p RateProfile, key string, c AntiAttackerConfig) RateProfile {
	if f.strikes.suspect(key, c.Strikes) {
		return halved(p)
	}
	return p
}

// banning reports whether a rate-limit violation may escalate to a ban.
//
// Only while frps is actually under attack. A quiet server has no business
// banning anyone: the throttle has already turned the attempt away, and the
// step from "you are asking too often" to "you are locked out for a minute" is
// the one that hurts a real client who happened to have a bad minute. Under
// attack that judgement flips - a source still overflowing its window is the
// thing the ban exists for.
//
// With the attack detector switched off there is no "under attack" to consult,
// so violations escalate as they always did. Turning the detector off must not
// quietly disable banning along with it.
func (f *Firewall) banning(c AntiAttackerConfig) bool {
	if !c.Attack.Enabled {
		return true
	}
	return f.attack.isUnder()
}

var verdictStruck = Verdict{Reason: "struck (not a client)"}

// IsUnderAttack reports whether the connection rate has crossed the threshold
// that makes the blunter measures worth their cost.
func (f *Firewall) IsUnderAttack() bool {
	f.mu.RLock()
	on := f.aa.Enabled && f.aa.Attack.Enabled
	f.mu.RUnlock()
	return on && f.attack.isUnder()
}

// HandshakeTimeout returns how long to wait for a peer to say something,
// shortening the caller's default while under attack.
//
// A connection that opens and stays silent costs a socket for the whole
// timeout, so this is the cheapest answer to a slow flood there is. It is also
// the one that would hurt honest clients on bad links if it were permanent,
// which is why it only applies while the attack state is on.
func (f *Firewall) HandshakeTimeout(def time.Duration) time.Duration {
	f.mu.RLock()
	ms := f.aa.Attack.InitialTimeoutMs
	on := f.aa.Enabled && f.aa.Attack.Enabled
	f.mu.RUnlock()
	if !on || ms <= 0 || !f.attack.isUnder() {
		return def
	}
	if d := time.Duration(ms) * time.Millisecond; d < def {
		return d
	}
	return def
}

// HandshakeByteLimit is how much a peer may send before it has finished
// identifying itself, or 0 for no limit.
//
// Not gated on the attack state, unlike the timeout it sits beside: the ceiling
// is far enough above anything a real client sends that leaving it armed costs
// nothing, and a peer spending our memory is worth cutting off whether or not
// the connection rate has crossed a line.
func (f *Firewall) HandshakeByteLimit() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if !f.aa.Enabled || !f.aa.Attack.Enabled {
		return 0
	}
	return f.aa.Attack.InitialBufferLimitBytes
}

// ReportProtocolFailure records that a peer failed to speak frp's protocol - a
// non-TLS connection to a TLS-only port, a login that did not verify.
//
// Worth more than any amount of counting: an frpc having a bad day still speaks
// frp. Something that does not is not a client, and after a few of these it is
// banned outright.
func (f *Firewall) ReportProtocolFailure(remoteAddr string) {
	f.mu.RLock()
	c := f.aa.Strikes
	on := f.aa.Enabled && c.Enabled && !f.inGrace(f.aa.GraceSeconds)
	f.mu.RUnlock()
	if !on {
		return
	}
	f.strikes.add(clientKey(remoteAddr, "", nil), strikeProtocol, c)
}

// NoteConnectionClosed is called when a user connection finishes, with how long
// it lasted and how many bytes crossed it. It feeds the two things that can
// only be known afterwards: whether the source earned trust, and whether it is
// scanning.
//
// One hook for both because they read the same evidence and disagree about it.
// A connection that lasted and carried traffic is somebody using the tunnel; a
// string of connections that carried nothing is somebody looking to see what is
// listening.
func (f *Firewall) NoteConnectionClosed(remoteAddr string, dur time.Duration, bytes int64) {
	f.mu.RLock()
	trust, strikes := f.aa.Trust, f.aa.Strikes
	on := f.aa.Enabled && !f.inGrace(f.aa.GraceSeconds)
	f.mu.RUnlock()
	if !on {
		return
	}
	key := clientKey(remoteAddr, "", nil)

	if trust.Enabled && dur >= time.Duration(trust.AfterMs)*time.Millisecond && bytes >= int64(trust.MinBytes) {
		f.trust.grant(key, trust)
		return
	}
	if strikes.Enabled && bytes < int64(strikes.EmptyBytes) {
		f.strikes.add(key, strikeEmpty, strikes)
	}
}

// AcquireConn takes a concurrency slot for the source, reporting false when it
// already holds as many connections as the profile allows. The returned release
// must be called when the connection ends; it is a no-op when the cap is off.
func (f *Firewall) AcquireConn(remoteAddr string) (ok bool, release func()) {
	f.mu.RLock()
	limit := f.aa.TCP.MaxConcurrent
	on := f.aa.Enabled && f.aa.TCP.Enabled && limit > 0 && !f.inGrace(f.aa.GraceSeconds)
	f.mu.RUnlock()
	if !on {
		return true, func() {}
	}
	key := clientKey(remoteAddr, "", nil)
	if !f.conc.acquire(key, limit) {
		return false, func() {}
	}
	return true, func() { f.conc.release(key) }
}

// AdmitTCP rate-limits one accepted user connection.
//
// Callers should close a refused connection with RST rather than a graceful
// close - see netpkg.CloseWithReset. A refusal that leaves a socket in
// TIME_WAIT for two minutes is a poor answer to a flood.
func (f *Firewall) AdmitTCP(remoteAddr string) Verdict {
	f.mu.RLock()
	c := f.aa
	on := c.Enabled
	f.mu.RUnlock()
	if !on {
		return verdictAllow
	}
	// Counted even when this proxy is out of scope and even during grace: the
	// attack state is a reading of the whole server's load, and one taken only
	// from the parts still being policed would be the wrong number.
	f.attack.note(c.Attack)

	if !c.TCP.Enabled {
		return verdictAllow
	}
	key := clientKey(remoteAddr, "", nil)
	if skip, refuse := f.exempt(key, c); skip {
		return verdictAllow
	} else if refuse {
		return verdictStruck
	}
	return f.tcpLimiter.admitBoth(key, f.profileFor(c.TCP, key, c), f.banning(c))
}

// AdmitHTTP rate-limits one request served by the vhost reverse proxy. xff is
// the raw X-Forwarded-For header, which is never believed: with the rules layer
// gone there is nothing left that says which peers are trusted proxies, so a
// request is always counted against the socket address it arrived from.
//
// Per request rather than per connection because the reverse proxy pools work
// connections by route: checking at connection setup would wave through every
// request that landed on an already-open one.
func (f *Firewall) AdmitHTTP(remoteAddr, xff string) Verdict {
	f.mu.RLock()
	c := f.aa
	on := c.Enabled && c.HTTP.Enabled
	f.mu.RUnlock()
	if !on {
		return verdictAllow
	}
	key := clientKey(remoteAddr, xff, nil)
	if skip, refuse := f.exempt(key, c); skip {
		return verdictAllow
	} else if refuse {
		return verdictStruck
	}
	return f.httpLimiter.admitBoth(key, f.profileFor(c.HTTP.RateProfile, key, c), f.banning(c))
}

// AdmitControl rate-limits one connection to the frps control port.
//
// Armed by its own AntiAttacker.Control.Protect switch.
//
// Note what a refusal means here, which is not what it means for a user
// connection: the peer is an frpc client, and turning it away keeps its tunnels
// down until it gets back in. The default limits are correspondingly loose.
func (f *Firewall) AdmitControl(remoteAddr string) Verdict {
	f.mu.RLock()
	c := f.aa
	on := c.Enabled && c.Control.Protect
	f.mu.RUnlock()
	if !on {
		return verdictAllow
	}
	f.attack.note(c.Attack)

	key := clientKey(remoteAddr, "", nil)
	if skip, refuse := f.exempt(key, c); skip {
		return verdictAllow
	} else if refuse {
		return verdictStruck
	}
	return f.ctlLimiter.admitBoth(key, f.profileFor(c.Control.RateProfile, key, c), f.banning(c))
}

// AdmitWeb rate-limits one connection to the dashboard port. Armed by
// AntiAttacker.Web.Protect.
//
// Worth knowing before turning it on: this page is what edits these settings.
// The limit is sized so a page load cannot trip it, but somebody who sets it
// very low can lock themselves out until frps_firewall.json is edited by hand.
func (f *Firewall) AdmitWeb(remoteAddr string) Verdict {
	f.mu.RLock()
	c := f.aa
	on := c.Enabled && c.Web.Protect
	f.mu.RUnlock()
	if !on {
		return verdictAllow
	}
	f.attack.note(c.Attack)

	key := clientKey(remoteAddr, "", nil)
	if skip, refuse := f.exempt(key, c); skip {
		return verdictAllow
	} else if refuse {
		return verdictStruck
	}
	return f.webLimiter.admitBoth(key, f.profileFor(c.Web.RateProfile, key, c), f.banning(c))
}

// AdmitSSH rate-limits one connection to the ssh tunnel gateway port. Armed by
// AntiAttacker.SSH.Protect.
func (f *Firewall) AdmitSSH(remoteAddr string) Verdict {
	f.mu.RLock()
	c := f.aa
	on := c.Enabled && c.SSH.Protect
	f.mu.RUnlock()
	if !on {
		return verdictAllow
	}
	f.attack.note(c.Attack)

	key := clientKey(remoteAddr, "", nil)
	if skip, refuse := f.exempt(key, c); skip {
		return verdictAllow
	} else if refuse {
		return verdictStruck
	}
	return f.sshLimiter.admitBoth(key, f.profileFor(c.SSH.RateProfile, key, c), f.banning(c))
}

// AdmitUDP rate-limits one UDP packet of size bytes, for the udp and pe proxies
// and the udp half of tcp+udp. It reports whether to forward the packet; a
// refusal is a silent drop, since UDP has no way to say no.
//
// Returns a bool rather than a Verdict: there is nowhere for a reason or a
// retry hint to go, and this runs per packet.
func (f *Firewall) AdmitUDP(remoteAddr string, size int) bool {
	f.mu.RLock()
	p := f.aa.UDP
	on := f.aa.Enabled && p.Enabled
	f.mu.RUnlock()
	if !on {
		return true
	}
	return f.udpLimiter.admit(clientKey(remoteAddr, "", nil), size, p)
}

// AntiAttackerStatus reports what the rate limiting is doing right now, as
// opposed to what it is configured to do.
//
// This exists because everything above is deliberately quiet: a rate-limit
// refusal writes no log line, since a flood being turned away must not become a
// flood of writes. That leaves no way to tell a working configuration from one
// that is off, and no way to find out who is being turned away - which is what
// somebody looking at this page actually wants to know.
func (f *Firewall) AntiAttackerStatus() Status {
	f.mu.RLock()
	c := f.aa
	on := c.Enabled
	f.mu.RUnlock()

	st := Status{Tracked: map[string]int{}}
	if !on {
		st.Bans = []BanEntry{}
		return st
	}
	now := f.nowMsFn()
	st.UnderAttack = c.Attack.Enabled && f.attack.isUnder()
	st.InGrace = f.inGrace(c.GraceSeconds)
	st.Trusted = f.trust.size()
	st.OpenConns = f.conc.size()
	st.Tracked = map[string]int{
		"tcp":     f.tcpLimiter.size(),
		"http":    f.httpLimiter.size(),
		"udp":     f.udpLimiter.size(),
		"control": f.ctlLimiter.size(),
		"web":     f.webLimiter.size(),
		"ssh":     f.sshLimiter.size(),
		"strikes": f.strikes.size(),
	}

	bans := make([]BanEntry, 0, 16)
	bans = append(bans, f.tcpLimiter.bans("tcp", now)...)
	bans = append(bans, f.httpLimiter.bans("http", now)...)
	bans = append(bans, f.ctlLimiter.bans("control", now)...)
	bans = append(bans, f.webLimiter.bans("web", now)...)
	bans = append(bans, f.sshLimiter.bans("ssh", now)...)
	bans = append(bans, f.strikes.bans(now)...)
	sort.Slice(bans, func(i, j int) bool { return bans[i].SecondsLeft > bans[j].SecondsLeft })
	st.Bans = bans
	return st
}

// ClearAntiAttackerBans lifts every ban and forgets every strike, for the
// operator who has just fixed whatever was tripping it and does not want to
// wait the ban out. Trust is kept: it was earned, and nothing here revokes it.
func (f *Firewall) ClearAntiAttackerBans() {
	f.tcpLimiter.reset()
	f.httpLimiter.reset()
	f.udpLimiter.reset()
	f.ctlLimiter.reset()
	f.webLimiter.reset()
	f.sshLimiter.reset()
	f.strikes.reset()
	f.conc.reset()
}

// RetryAfterSeconds is what an HTTP 429 should advertise for this verdict: the
// configured override when set, otherwise however long the source actually has
// to wait, rounded up so a client that obeys it does not come back too early.
func (f *Firewall) RetryAfterSeconds(v Verdict) int {
	f.mu.RLock()
	override := f.aa.HTTP.RetryAfterSec
	f.mu.RUnlock()
	if override > 0 {
		return override
	}
	return max(int((v.RetryAfter+time.Second-1)/time.Second), 1)
}

// --- internals (call with f.mu held) ---

func (f *Firewall) saveLocked() error {
	if f.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(Config{AntiAttacker: f.aa, KernelBan: f.banCfg}, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// --- helpers ---

// parseAddr reads the source address of a connection. netip rather than net.IP:
// an Addr is a value, so this allocates nothing on a path that runs for every
// user connection and, for udp proxies, every packet.
func parseAddr(remoteAddr string) netip.Addr {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}
	}
	// An IPv4 client accepted on a dual-stack listener arrives as
	// ::ffff:a.b.c.d. Unmapping it is what keeps one peer to one key.
	return addr.Unmap()
}
