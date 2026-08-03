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

//go:build linux

package firewall

import (
	"context"
	"net/netip"
	"os/exec"
	"strconv"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/util/log"
)

const (
	// ipsetV4 and ipsetV6 are ours alone. Two sets because an ipset holds one
	// address family, and a name nobody else would pick so draining can be
	// unconditional - we only ever destroy what we created.
	ipsetV4 = "frps-ban4"
	ipsetV6 = "frps-ban6"

	// banQueueDepth bounds how many bans may be waiting to reach the kernel.
	// Programming one is an exec, which is slow next to the map write that
	// decided it, so the admission path hands off and moves on. Full means the
	// host cannot keep up, and dropping is right: the ban is already in force
	// in this process, and the kernel copy is an optimisation.
	banQueueDepth = 1024

	// ipsetTimeout bounds one ipset or iptables call. These are local
	// processes; one that has not answered in this long is stuck.
	ipsetTimeout = 5 * time.Second
)

type ipsetRequest struct {
	ip  netip.Addr
	ttl time.Duration
}

// ipsetSink drops banned sources in the kernel using ipset plus one iptables
// rule per family.
//
// Entries carry ipset's own timeout, so the kernel expires them without this
// process tracking anything. That matters more than it looks: bans here expire
// lazily - nobody notices one has run out until the source tries again - so
// there is no expiry event to hang a removal on. Handing the deadline to the
// kernel sidesteps the whole problem.
type ipsetSink struct {
	queue chan ipsetRequest

	stopOnce sync.Once
	stop     chan struct{}
	done     chan struct{}

	// families records what was actually created, so drain removes exactly
	// that and a half-built setup does not leave a rule pointing at a set that
	// is gone.
	mu       sync.Mutex
	families []string
}

// newPlatformBanSink builds the ipset sink, or the no-op when this host cannot
// run one. required says the operator asked for ipset by name rather than
// leaving it to auto, which only changes how loudly the fallback is reported.
func newPlatformBanSink(required bool) banSink {
	missing := ""
	for _, tool := range []string{"ipset", "iptables"} {
		if _, err := exec.LookPath(tool); err != nil {
			missing = tool
			break
		}
	}
	if missing != "" {
		report := log.Infof
		if required {
			report = log.Warnf
		}
		report("[FW] kernel ban is off: %s is not installed, so bans are enforced in frps only", missing)
		return noopSink{}
	}

	s := &ipsetSink{
		queue: make(chan ipsetRequest, banQueueDepth),
		stop:  make(chan struct{}),
		done:  make(chan struct{}),
	}

	// A previous run may have died with its set still loaded. Destroy before
	// creating so the set starts empty and holds only bans this run decided -
	// the ledger it mirrors is empty at startup too.
	s.teardown()

	if !s.setup() {
		report := log.Infof
		if required {
			report = log.Warnf
		}
		report("[FW] kernel ban is off: could not program the host firewall, most likely missing CAP_NET_ADMIN")
		s.teardown()
		return noopSink{}
	}

	go s.run()

	log.Infof("[FW] kernel ban is on: banned sources are dropped by the kernel via ipset")
	return s
}

func (s *ipsetSink) name() string { return "ipset" }

func (s *ipsetSink) ban(ip netip.Addr, ttl time.Duration) {
	select {
	case s.queue <- ipsetRequest{ip: ip, ttl: ttl}:
	default:
		// The ban still stands in this process; only the kernel copy is lost.
	}
}

func (s *ipsetSink) drain() {
	s.stopOnce.Do(func() {
		close(s.stop)
		<-s.done
		s.teardown()
	})
}

func (s *ipsetSink) run() {
	defer close(s.done)
	for {
		select {
		case <-s.stop:
			return
		case r := <-s.queue:
			s.add(r)
		}
	}
}

func (s *ipsetSink) add(r ipsetRequest) {
	set := ipsetV4
	if r.ip.Is6() {
		set = ipsetV6
	}
	seconds := int(r.ttl / time.Second)
	if seconds < 1 {
		seconds = 1
	}
	// -exist so a source banned again while still listed refreshes its
	// deadline instead of failing.
	run("ipset", "add", set, r.ip.String(), "timeout", strconv.Itoa(seconds), "-exist")
}

// setup creates the sets and points one rule at each. Reports whether anything
// at all was installed.
func (s *ipsetSink) setup() bool {
	ok := false

	for _, f := range []struct{ set, family, cmd string }{
		{ipsetV4, "inet", "iptables"},
		{ipsetV6, "inet6", "ip6tables"},
	} {
		if _, err := exec.LookPath(f.cmd); err != nil {
			continue
		}
		// timeout 0 makes the set support per-entry deadlines with no default
		// of its own, which is what lets each ban carry its own.
		if !run("ipset", "create", f.set, "hash:ip", "family", f.family, "timeout", "0", "-exist") {
			continue
		}
		// -I puts it first: a DROP that sits behind somebody else's ACCEPT
		// would never be reached.
		if !run(f.cmd, "-I", "INPUT", "-m", "set", "--match-set", f.set, "src", "-j", "DROP") {
			run("ipset", "destroy", f.set)
			continue
		}

		s.mu.Lock()
		s.families = append(s.families, f.set+"|"+f.cmd)
		s.mu.Unlock()
		ok = true
	}

	return ok
}

// teardown removes the rule and the set, leaving the host as it was found.
//
// Called when the sink is switched off, on shutdown, and once at startup to
// clear what a previous run may have left behind. Every step is allowed to
// fail: there is nothing to clean up on a first run, and a half-removed setup
// is worse than a noisy log.
func (s *ipsetSink) teardown() {
	for _, f := range []struct{ set, cmd string }{
		{ipsetV4, "iptables"},
		{ipsetV6, "ip6tables"},
	} {
		if _, err := exec.LookPath(f.cmd); err == nil {
			// -D repeatedly: a restart that failed to clean up could have left
			// more than one copy, and each -D removes one.
			for range 4 {
				if !run(f.cmd, "-D", "INPUT", "-m", "set", "--match-set", f.set, "src", "-j", "DROP") {
					break
				}
			}
		}
		run("ipset", "destroy", f.set)
	}

	s.mu.Lock()
	s.families = nil
	s.mu.Unlock()
}

// run executes one command and reports whether it succeeded. Output is
// discarded: these either work or they do not, and the failure that matters -
// no permission to program the firewall - is reported once by the caller.
func run(name string, args ...string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), ipsetTimeout)
	defer cancel()
	return exec.CommandContext(ctx, name, args...).Run() == nil
}
