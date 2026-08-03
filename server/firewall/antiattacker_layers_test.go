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

// Tests for the layers that are not rate limiting: the grace period, the attack
// state, trust, strikes, the global tier, the concurrency cap and the status
// report.
package firewall

import (
	"strconv"
	"strings"
	"testing"
	"time"
)

// --- grace period ---

// A restart is a burst frps causes itself: every frpc reconnects at once. The
// first thing a fresh server does must not be banning the clients it serves.
func TestGracePeriodSuspendsEverything(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true, GraceSeconds: 3600,
		TCP:     RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1},
		Control: ControlProfile{Protect: true, RateProfile: RateProfile{WindowMs: 60000, MaxPerWindow: 1}},
	})
	for range 50 {
		if !f.AdmitTCP("1.2.3.4:1000").Allowed {
			t.Fatal("a proxy connection was refused during the grace period")
		}
		if !f.AdmitControl("1.2.3.4:1000").Allowed {
			t.Fatal("an frpc reconnect was refused during the grace period")
		}
	}
	if !f.AntiAttackerStatus().InGrace {
		t.Fatal("status does not report the grace period, so a fresh server looks broken")
	}
}

func TestGraceOffMeansLimitsApplyImmediately(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true, // GraceSeconds 0
		TCP:     RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1, BanViolations: 99},
	})
	f.AdmitTCP("1.2.3.4:1000")
	if f.AdmitTCP("1.2.3.4:1000").Allowed {
		t.Fatal("with no grace configured the limit should bite at once")
	}
}

// --- attack state ---

func TestAttackStateTurnsOnAndCoolsDown(t *testing.T) {
	c := &fakeClock{ms: 1_000_000}
	a := newAttackState(c.now)
	cfg := AttackConfig{Enabled: true, ConnectionsPerSec: 5, CooldownSec: 3}

	for range 10 { // a busy second
		a.note(cfg)
	}
	if a.isUnder() {
		t.Fatal("the state flipped before the second was over; it is judged when the second ends")
	}
	c.advance(1 * time.Second)
	a.note(cfg)
	if !a.isUnder() {
		t.Fatal("a second over the threshold did not raise the attack state")
	}

	// Quiet seconds: the state must hold until the cooldown has fully elapsed,
	// or a flood pacing itself around the line would flip it back and forth.
	for range 2 {
		c.advance(1 * time.Second)
		a.note(cfg)
		if !a.isUnder() {
			t.Fatal("attack state dropped before the cooldown elapsed")
		}
	}
	c.advance(3 * time.Second)
	a.note(cfg)
	if a.isUnder() {
		t.Fatal("attack state never cleared after a quiet cooldown")
	}
}

// The end of a flood is exactly when nothing calls in, so the state must clear
// on the clock alone. Held as a flag set on the way up, it stayed up until the
// next connection happened to arrive - which on a server that had just been
// flooded off the air could be a very long time, with the shortened handshake
// timeout working against honest clients the whole while.
func TestAttackStateClearsWithNoTrafficAtAll(t *testing.T) {
	c := &fakeClock{ms: 1_000_000}
	a := newAttackState(c.now)
	cfg := AttackConfig{Enabled: true, ConnectionsPerSec: 5, CooldownSec: 3}

	for range 10 {
		a.note(cfg)
	}
	c.advance(1 * time.Second)
	a.note(cfg)
	if !a.isUnder() {
		t.Fatal("a second over the threshold did not raise the attack state")
	}

	// The flood stops dead. Nothing calls note again, ever.
	c.advance(4 * time.Second)
	if a.isUnder() {
		t.Fatal("attack state never cleared once the flood stopped, so it would stay up until the next client arrived")
	}
}

func TestAttackStateOffByDefault(t *testing.T) {
	c := &fakeClock{ms: 1_000_000}
	a := newAttackState(c.now)
	for range 1000 {
		a.note(AttackConfig{ConnectionsPerSec: 1}) // Enabled false
	}
	if a.isUnder() {
		t.Fatal("attack state engaged while disabled")
	}
}

func TestHandshakeTimeoutNeverExceedsTheCallersOwnValue(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		Attack:  AttackConfig{Enabled: true, ConnectionsPerSec: 1, CooldownSec: 60, InitialTimeoutMs: 2000},
	})
	if got := f.HandshakeTimeout(10 * time.Second); got != 10*time.Second {
		t.Fatalf("timeout = %v while calm, want the caller's 10s untouched", got)
	}
	if got := f.HandshakeTimeout(1 * time.Second); got != 1*time.Second {
		t.Fatalf("timeout = %v, must never exceed what the caller asked for", got)
	}
}

// --- trust ---

// The point of trust: it is what makes a tight limit safe, because the people
// who actually use the tunnel stop being measured.
func TestTrustExemptsAfterRealUse(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		TCP:     RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1, BanViolations: 99},
		Trust:   TrustConfig{Enabled: true, AfterMs: 1000, MinBytes: 100, ForSeconds: 3600},
	})
	const addr = "1.2.3.4:1000"
	f.AdmitTCP(addr)
	if f.AdmitTCP(addr).Allowed {
		t.Fatal("limit did not apply before trust was earned")
	}

	// A connection that lasted and carried traffic.
	f.NoteConnectionClosed(addr, 5*time.Second, 4096)

	for range 20 {
		if !f.AdmitTCP(addr).Allowed {
			t.Fatal("a trusted source was still being rate limited")
		}
	}
}

func TestTrustNotGrantedForShortOrSilentConnections(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		TCP:     RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1, BanViolations: 99},
		Trust:   TrustConfig{Enabled: true, AfterMs: 1000, MinBytes: 100, ForSeconds: 3600},
	})
	// Long but silent is a slowloris, not a user; busy but brief is a probe.
	f.NoteConnectionClosed("1.1.1.1:1", 5*time.Second, 10)
	f.NoteConnectionClosed("2.2.2.2:1", 10*time.Millisecond, 999999)

	for _, a := range []string{"1.1.1.1:1", "2.2.2.2:1"} {
		f.AdmitTCP(a)
		if f.AdmitTCP(a).Allowed {
			t.Fatalf("%s was trusted without earning it", a)
		}
	}
}

// --- strikes ---

// The signal a rate limit can never see: the scanner in the live log connected
// six times over sixteen hours, which is nothing to count, and moved almost no
// bytes each time, which is everything.
func TestEmptyConnectionsEarnAStrikeBan(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		TCP:     RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1000},
		Strikes: StrikeConfig{Enabled: true, EmptyConnections: 3, EmptyBytes: 64, BanSeconds: 600, ForgetMs: 3600000},
	})
	const addr = "103.78.1.215:5000"
	for range 3 {
		f.NoteConnectionClosed(addr, 50*time.Millisecond, 10)
	}
	v := f.AdmitTCP(addr)
	if v.Allowed {
		t.Fatal("a source with three empty connections was still admitted")
	}
	if v.Reason == "" {
		t.Fatal("strike refusal carried no reason")
	}
}

func TestProtocolFailuresEarnAStrikeBan(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		Control: ControlProfile{Protect: true, RateProfile: RateProfile{WindowMs: 60000, MaxPerWindow: 1000}},
		Strikes: StrikeConfig{Enabled: true, ProtocolFailures: 3, BanSeconds: 600, ForgetMs: 3600000},
	})
	const addr = "103.78.1.215:5000"
	for range 3 {
		f.ReportProtocolFailure(addr)
	}
	if f.AdmitControl(addr).Allowed {
		t.Fatal("a peer that failed the protocol three times still reached the control port")
	}
}

func TestRealTrafficDoesNotEarnStrikes(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		TCP:     RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1000},
		Strikes: StrikeConfig{Enabled: true, EmptyConnections: 2, EmptyBytes: 64, BanSeconds: 600, ForgetMs: 3600000},
	})
	const addr = "1.2.3.4:1000"
	for range 20 {
		f.NoteConnectionClosed(addr, time.Second, 1_000_000)
	}
	if !f.AdmitTCP(addr).Allowed {
		t.Fatal("a source doing real work collected strikes")
	}
}

func TestStrikesOffByDefault(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		TCP:     RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1000},
	})
	const addr = "1.2.3.4:1000"
	for range 50 {
		f.NoteConnectionClosed(addr, time.Millisecond, 0)
		f.ReportProtocolFailure(addr)
	}
	if !f.AdmitTCP(addr).Allowed {
		t.Fatal("strikes acted while the group was switched off")
	}
}

// --- global tier and concurrency ---

func TestGlobalTierCatchesWidelySpreadTraffic(t *testing.T) {
	l, _ := newTestLimiter()
	p := testProfile()
	p.MaxPerWindow = 10       // per-source: one attempt each, never reached
	p.SubnetMaxPerWindow = 10 // every address sits in a different /24
	p.GlobalMaxPerWindow = 4

	allowed := 0
	for i := range 12 {
		if l.admitBoth(strconv.Itoa(10+i)+".0.0.1", p, true).Allowed {
			allowed++
		}
	}
	if allowed != 4 {
		t.Fatalf("allowed %d of 12 sources in 12 different blocks, want 4 (the global ceiling)", allowed)
	}
}

func TestConcurrencyCapAndRelease(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		TCP:     RateProfile{Enabled: true, WindowMs: 60000, MaxPerWindow: 1000, MaxConcurrent: 2},
	})
	const addr = "1.2.3.4:1000"
	ok1, rel1 := f.AcquireConn(addr)
	ok2, rel2 := f.AcquireConn(addr)
	ok3, _ := f.AcquireConn(addr)
	if !ok1 || !ok2 {
		t.Fatal("the first two connections were refused below the cap of 2")
	}
	if ok3 {
		t.Fatal("a third concurrent connection got through a cap of 2")
	}
	rel1()
	if ok, _ := f.AcquireConn(addr); !ok {
		t.Fatal("releasing a slot did not free it")
	}
	rel2()
}

// --- status ---

func TestStatusListsBansAndClearLiftsThem(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		Control: ControlProfile{Protect: true, RateProfile: RateProfile{WindowMs: 60000, MaxPerWindow: 1000}},
		Strikes: StrikeConfig{Enabled: true, ProtocolFailures: 1, BanSeconds: 600, ForgetMs: 3600000},
	})
	f.ReportProtocolFailure("9.9.9.9:1")

	st := f.AntiAttackerStatus()
	if len(st.Bans) != 1 {
		t.Fatalf("status listed %d bans, want 1", len(st.Bans))
	}
	if st.Bans[0].Source != "9.9.9.9" || st.Bans[0].Tier != "strike" {
		t.Fatalf("ban entry = %+v, want the struck source", st.Bans[0])
	}
	if st.Bans[0].SecondsLeft <= 0 {
		t.Fatal("ban entry has no time left, so the dashboard cannot show a countdown")
	}

	f.ClearAntiAttackerBans()
	if got := len(f.AntiAttackerStatus().Bans); got != 0 {
		t.Fatalf("%d bans survived a clear", got)
	}
	if !f.AdmitControl("9.9.9.9:1").Allowed {
		t.Fatal("a cleared source is still being refused")
	}
}

// The aggregate buckets throttle and can never be banned, so they must never
// appear as a banned "source" in the dashboard.
func TestStatusHidesAggregateBuckets(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		TCP: RateProfile{
			Enabled: true, WindowMs: 60000, MaxPerWindow: 1, BanViolations: 1,
			SubnetMaxPerWindow: 1, GlobalMaxPerWindow: 1,
		},
	})
	for i := range 6 {
		f.AdmitTCP("5.252.83." + strconv.Itoa(i) + ":1")
	}
	for _, b := range f.AntiAttackerStatus().Bans {
		if strings.HasPrefix(b.Source, "net:") {
			t.Fatalf("an aggregate bucket appeared as a banned source: %+v", b)
		}
	}
}

func TestStatusIsEmptyWhenDisabled(t *testing.T) {
	f := newTestFirewall(t, nil)
	st := f.AntiAttackerStatus()
	if st.UnderAttack || len(st.Bans) != 0 {
		t.Fatalf("status = %+v, want nothing reported while AntiAttacker is off", st)
	}
}

// --- bans are gated on the attack state ---

// A quiet server has no business banning anyone. The throttle already turned
// the attempt away; the step to "locked out for a minute" is the one that hurts
// a real client having a bad minute, and nothing is under attack to justify it.
func TestViolationsDoNotBanWhileCalm(t *testing.T) {
	c := &fakeClock{ms: 1_000_000}
	l := newLimiter(c.now)
	p := RateProfile{Enabled: true, WindowMs: 1000, MaxPerWindow: 1, BanViolations: 2, BanSeconds: 60, IdleForgetMs: 60000, MaxTracked: 100}

	for range 5 {
		l.admit("1.2.3.4", p, false) // fills the window
		if v := l.admit("1.2.3.4", p, false); v.Banned {
			t.Fatal("a ban was handed out while nothing was under attack")
		}
		c.advance(1100 * time.Millisecond) // next window, another violation
	}
}

// The violations still accumulate while calm, so a source that keeps it up into
// an attack is banned on the spot rather than starting its count over.
func TestViolationsCarryIntoTheAttack(t *testing.T) {
	c := &fakeClock{ms: 1_000_000}
	l := newLimiter(c.now)
	p := RateProfile{Enabled: true, WindowMs: 1000, MaxPerWindow: 1, BanViolations: 2, BanSeconds: 60, IdleForgetMs: 60000, MaxTracked: 100}

	// Two violations while calm: throttled both times, never banned.
	for range 2 {
		l.admit("1.2.3.4", p, false)
		if v := l.admit("1.2.3.4", p, false); v.Banned {
			t.Fatal("banned while calm")
		}
		c.advance(1100 * time.Millisecond)
	}

	// The attack starts. The next overflow finds the count already there.
	l.admit("1.2.3.4", p, true)
	if v := l.admit("1.2.3.4", p, true); !v.Banned {
		t.Fatal("the violations counted while calm did not carry into the attack")
	}
}

// The gate itself: only while under attack, unless the detector is switched
// off - turning the detector off must not quietly disable banning as well.
func TestBanningGate(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		Attack:  AttackConfig{Enabled: true, ConnectionsPerSec: 2, CooldownSec: 60},
	})
	c := f.Snapshot().AntiAttacker

	if f.banning(c) {
		t.Error("bans allowed on a calm server")
	}

	// Push the rate over the line, then let the second finish so it is judged.
	for range 5 {
		f.attack.note(c.Attack)
	}
	f.attack.overAt = f.nowMsFn()
	if !f.banning(c) {
		t.Error("bans withheld while under attack")
	}

	off := c
	off.Attack.Enabled = false
	if !f.banning(off) {
		t.Error("switching the attack detector off also disabled banning")
	}
}

// --- the suspect tier ---

// A source with strikes short of a ban used to be measured exactly like a
// source with a clean record: the evidence sat in the ledger unused until the
// last strike landed. It now buys a tighter budget instead.
func TestStrikesShortOfABanHalveTheBudget(t *testing.T) {
	aa := AntiAttackerConfig{
		Enabled: true,
		Control: ControlProfile{Protect: true, RateProfile: RateProfile{
			WindowMs: 60000, MaxPerWindow: 4, BanViolations: 99,
		}},
		Strikes: StrikeConfig{Enabled: true, ProtocolFailures: 3, BanSeconds: 60, ForgetMs: 300000, MaxTracked: 100},
		Attack:  AttackConfig{Enabled: true, ConnectionsPerSec: 1, CooldownSec: 60},
	}

	// Clean record: the full allowance of four.
	clean := newAAFirewall(t, aa)
	for i := range 4 {
		if !clean.AdmitControl("1.2.3.4:1000").Allowed {
			t.Fatalf("a clean source was refused on attempt %d of 4", i+1)
		}
	}
	if clean.AdmitControl("1.2.3.4:1000").Allowed {
		t.Fatal("the fifth attempt was allowed past a limit of four")
	}

	// One failed protocol attempt - not enough to ban - and the same source
	// gets half.
	marked := newAAFirewall(t, aa)
	marked.ReportProtocolFailure("1.2.3.4:1000")

	for i := range 2 {
		if !marked.AdmitControl("1.2.3.4:1000").Allowed {
			t.Fatalf("a suspect source was refused on attempt %d of 2", i+1)
		}
	}
	if marked.AdmitControl("1.2.3.4:1000").Allowed {
		t.Fatal("a source with a strike against it still got the full allowance")
	}
}

// Trust outranks the ledger: a source that has proved itself is not measured at
// all, whatever it did before.
func TestTrustedSourceIsNotHalved(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		Control: ControlProfile{Protect: true, RateProfile: RateProfile{
			WindowMs: 60000, MaxPerWindow: 2, BanViolations: 99,
		}},
		Strikes: StrikeConfig{Enabled: true, ProtocolFailures: 3, BanSeconds: 60, ForgetMs: 300000, MaxTracked: 100},
	})
	cfg := f.Snapshot()
	cfg.Rules = []Rule{{ID: "office", Action: "allow", CIDR: "1.2.3.4", Port: "all", Trusted: true}}
	if err := f.SetConfig(cfg); err != nil {
		t.Fatalf("set config: %v", err)
	}
	f.ReportProtocolFailure("1.2.3.4:1000")

	for range 20 {
		if !f.AdmitControl("1.2.3.4:1000").Allowed {
			t.Fatal("a trusted source was measured because it had a strike")
		}
	}
}

func TestHalvedRoundsUpAndLeavesTheWideTiersAlone(t *testing.T) {
	p := RateProfile{
		MaxPerWindow: 5, BanViolations: 3,
		SubnetMaxPerWindow: 10, GlobalMaxPerWindow: 100,
	}
	h := halved(p)

	if h.MaxPerWindow != 3 {
		t.Errorf("MaxPerWindow = %d, want 3 - halving must round up so a limit of 1 never becomes 0", h.MaxPerWindow)
	}
	if h.BanViolations != 2 {
		t.Errorf("BanViolations = %d, want 2", h.BanViolations)
	}
	if h.SubnetMaxPerWindow != 10 || h.GlobalMaxPerWindow != 100 {
		t.Error("the wider tiers were halved; they count everyone together, so one suspect would throttle its neighbors")
	}

	// A limit of one has nowhere to go and must stay usable.
	if got := halved(RateProfile{MaxPerWindow: 1, BanViolations: 1}); got.MaxPerWindow != 1 || got.BanViolations != 1 {
		t.Errorf("halving a limit of one gave %+v, want it left alone", got)
	}
	// The never-ban sentinel must survive, or the wide tiers would start banning.
	if got := halved(RateProfile{BanViolations: maxInt}); got.BanViolations != maxInt {
		t.Error("halving turned the never-ban sentinel into a reachable count")
	}
}
