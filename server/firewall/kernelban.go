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
	"time"
)

// KernelBanConfig asks the host firewall to drop a banned source's packets, so
// a peer that keeps coming back stops reaching frps at all.
//
// Everything else in this package makes refusing cheap. This makes it free: the
// packet dies in the kernel and never becomes an accepted socket, a goroutine
// and a map lookup. On a small VPS - which is where frps usually lives - that
// is the difference that decides whether a flood costs anything.
//
// Off by default and deliberately so. frps writing to the host firewall is a
// thing an operator has to agree to, not something it should start doing after
// an upgrade.
type KernelBanConfig struct {
	Enabled bool `json:"enabled"`

	// Backend picks how the ban is enforced. "auto" - the default - uses
	// whatever this host offers and falls back to doing nothing. "off" is the
	// same as Enabled being false, spelled where a reader is looking.
	Backend string `json:"backend,omitempty"` // auto | ipset | off
}

// banSink is where a ban goes to be enforced outside this process.
//
// The sink is a place bans are *carried out*, never where they are *kept*. The
// in-process ledger stays the only source of truth, which is what makes the
// switch safe to flip: turning the sink on or off changes where a packet dies,
// not who is banned. A sink that owned the list would lose every ban when it
// was turned off, and disagree with the ledger when it came back.
type banSink interface {
	// ban asks for ip to be dropped for ttl. Called on the admission path, so
	// it must not block: an implementation that talks to the kernel does it on
	// its own goroutine.
	ban(ip netip.Addr, ttl time.Duration)

	// drain removes everything this sink added, leaving the host as it was
	// found. Called when the sink is switched off, and on shutdown.
	drain()

	// name is what the logs call this backend.
	name() string
}

// noopSink is what every host gets until one is asked for, and what a host that
// cannot offer a real one falls back to.
type noopSink struct{}

func (noopSink) ban(netip.Addr, time.Duration) {}
func (noopSink) drain()                        {}
func (noopSink) name() string                  { return "off" }

// newBanSink builds the sink for this host, or the no-op when the config says
// so, the platform has nothing to offer, or the tools are missing.
//
// Never returns an error: a host firewall that cannot be programmed is a
// missing optimisation, not a reason for frps to refuse to start. What it does
// instead is say so once, in the log, so the operator who turned this on finds
// out that it did not take.
func newBanSink(c KernelBanConfig) banSink {
	if !c.Enabled || c.Backend == "off" {
		return noopSink{}
	}
	switch c.Backend {
	case "", "auto", "ipset":
		return newPlatformBanSink(c.Backend == "ipset")
	default:
		return noopSink{}
	}
}

// applyKernelBanLocked swaps the sink when the configuration changes.
//
// Turning it off drains the old one, so the addresses frps put in the host
// firewall come back out. Leaving them there would be the worst of both worlds:
// blocked in the kernel, invisible to the dashboard, and outliving the ban that
// put them there.
//
// Turning it on does not backfill the bans already being served. They are still
// enforced here, and each will be pushed down the moment the source tries
// again - which for a source worth banning is immediately.
func (f *Firewall) applyKernelBanLocked(c KernelBanConfig) {
	if c == f.banCfg && f.banSink != nil {
		return
	}

	old := f.banSink
	f.banCfg = c
	f.banSink = newBanSink(c)

	// Drained off the lock: teardown shells out to the host firewall, and
	// nothing else may be waiting on this mutex for that long.
	if old != nil {
		go old.drain()
	}
}

// CloseKernelBan takes frps back out of the host firewall. Called on shutdown;
// safe to call when the feature was never on.
func (f *Firewall) CloseKernelBan() {
	f.mu.Lock()
	sink := f.banSink
	f.banSink = noopSink{}
	f.mu.Unlock()

	if sink != nil {
		sink.drain()
	}
}

// noteBan is what the ledgers call when a ban is handed out. key is a source
// key, which for every path that bans is an address.
//
// The wider rate tiers share a key that is not an address ("net:..."), and they
// are configured never to ban anyway; parsing is what keeps a change to either
// of those from quietly programming the kernel with nonsense.
func (f *Firewall) noteBan(key string, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	ip, err := netip.ParseAddr(key)
	if err != nil {
		return
	}

	f.mu.RLock()
	sink := f.banSink
	f.mu.RUnlock()

	if sink != nil {
		sink.ban(ip.Unmap(), ttl)
	}
}
