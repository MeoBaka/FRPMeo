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
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/util/log"
)

// Surface is one of the doors into frps. Each keeps its own counters, because
// "the dashboard is being probed" and "somebody keeps hitting the control port"
// are different events that want telling apart, and a single set of numbers
// covering both would say neither.
type Surface string

const (
	// SurfaceControl is where clients connect: the tcp control port and the
	// kcp and quic listeners beside it.
	SurfaceControl Surface = "control"
	// SurfaceWeb is the dashboard.
	SurfaceWeb Surface = "web"
	// SurfaceProxy is user traffic arriving on the published proxy ports.
	SurfaceProxy Surface = "proxy"
	// SurfaceSSH is the ssh tunnel gateway.
	SurfaceSSH Surface = "ssh"
)

// surfaces is the whole set, fixed rather than created on demand: a monitor per
// proxy port would grow and shrink with the proxies, and a map that a remote
// peer can make entries in is the shape of the problem this package exists to
// avoid.
var surfaces = []Surface{SurfaceControl, SurfaceWeb, SurfaceProxy, SurfaceSSH}

const (
	// reportIntervalMs is how often a run of refusals gets a summary line.
	reportIntervalMs = 5000

	// maxReportedSources bounds the distinct-source set. Refusals from many
	// addresses are exactly the case where it would grow without limit, so the
	// count saturates instead of the memory.
	maxReportedSources = 4096

	// maxReportedReasons caps how many refusal reasons a line names before the
	// rest are summed into a remainder. Keeps one line one line.
	maxReportedReasons = 5

	// maxNamedRefusals is how many refusals a period names one at a time before
	// the reporting switches to a summary.
	//
	// A trickle is easier to read as a line each - which address, which reason -
	// and costs nothing to write. Past that the lines stop being information and
	// become the flood, which is what the summary is for.
	maxNamedRefusals = 5
)

// monitor turns what a surface decided into a report every reportIntervalMs
// instead of a line per connection.
//
// A line per connection is the wrong shape for this. At high rates it is the
// busiest thing on the host, and it answers the question badly besides: a
// thousand identical lines say what a count and a reason say better. What an
// operator wants from a run of refusals is how much, from how many, why, and
// whether anything real is still getting through - all of which are properties
// of a period rather than of a connection.
//
// Reporting starts on the first refusal and stops when refusals do, so a quiet
// server writes nothing at all.
type monitor struct {
	mu sync.Mutex

	// name identifies which surface this is.
	name string

	// The episode: everything since the reporting switched to summaries.
	// Below that threshold refusals are named one at a time and no episode is
	// opened.
	active       bool
	episodeStart int64
	epAllowed    int64
	epRefused    int64

	// named counts the refusals this period has already reported on their own.
	named int

	// The current period, cleared every report.
	periodStart int64
	allowed     int64
	refused     int64
	refusedBy   map[string]int64
	allowedBy   map[string]int64
	sources     map[string]struct{}
	moreSources bool

	// Peak connections in any one wall second of the period, which is the
	// number that says how hard this is being pushed - an average over five
	// seconds hides a burst that lasted one.
	second   int64
	inSecond int64
	peak     int64
}

func newMonitor(name string) *monitor {
	return &monitor{
		name:      name,
		refusedBy: make(map[string]int64),
		allowedBy: make(map[string]int64),
		sources:   make(map[string]struct{}),
	}
}

// NoteDecision records what a surface decided about one connection.
//
// Every caller that can refuse a peer should report both outcomes. Refusals
// alone cannot tell whether anything real is still getting through, and the
// periodic line needs both to mean anything.
//
// reason is what would have gone in a log line - it is what the report counts
// by, so the summary names what is happening and not only how much of it.
func (f *Firewall) NoteDecision(s Surface, allowed bool, reason, remoteAddr string) {
	m := f.monitors[s]
	if m == nil {
		return
	}
	if line := m.note(f.nowMsFn(), allowed, reason, remoteAddr); line != "" {
		log.Warnf("%s", line)
	}
}

// reportSurfaces is the periodic summary for every surface at once. On its own
// goroutine rather than driven by arriving connections, so the line that says
// the refusals stopped arrives when they stop and not when the next peer
// happens to turn up.
func (f *Firewall) reportSurfaces() {
	t := time.NewTicker(reportIntervalMs * time.Millisecond)
	defer t.Stop()

	for range t.C {
		now := f.nowMsFn()
		for _, s := range surfaces {
			if line := f.monitors[s].tick(now); line != "" {
				log.Warnf("%s", line)
			}
		}
	}
}

// note records one decision. It returns a line to log immediately, which
// happens for each refusal until there are too many to name: waiting up to five
// seconds to mention one would make a single denied client look like nothing
// happened at all.
func (m *monitor) note(now int64, allowed bool, reason, remote string) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.periodStart == 0 {
		m.periodStart = now
	}

	if sec := now / 1000; sec != m.second {
		if m.inSecond > m.peak {
			m.peak = m.inSecond
		}
		m.second = sec
		m.inSecond = 0
	}
	m.inSecond++

	if allowed {
		m.allowed++
		m.allowedBy[reason]++
	} else {
		m.refused++
		m.refusedBy[reason]++
	}

	if len(m.sources) < maxReportedSources {
		m.sources[hostOf(remote)] = struct{}{}
	} else {
		m.moreSources = true
	}

	if allowed {
		return ""
	}

	// Already summarizing: the periodic line covers this one.
	if m.active {
		return ""
	}

	m.named++
	if m.named > maxNamedRefusals {
		// Too many to keep naming. Switch to summaries from here, and let the
		// next tick be the one that speaks.
		m.active = true
		m.episodeStart = m.periodStart
		return ""
	}

	return fmt.Sprintf("[FW] %s: refused %s reason: %s", m.name, remote, reason)
}

// tick is the periodic report. It returns the line to log, or "" when there is
// nothing worth saying.
func (m *monitor) tick(now int64) string {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.active {
		// A trickle: every refusal was already named on its own, so there is
		// nothing to summarize and no episode to close.
		m.resetPeriod(now)
		return ""
	}

	m.epAllowed += m.allowed
	m.epRefused += m.refused

	// Refusals have stopped: the episode is over.
	if m.refused == 0 {
		line := fmt.Sprintf("[FW] %s: refusals stopped - refused %d, allowed %d over %s",
			m.name, m.epRefused, m.epAllowed, since(m.episodeStart, now))

		m.active = false
		m.epRefused, m.epAllowed, m.episodeStart = 0, 0, 0
		m.resetPeriod(now)

		return line
	}

	if m.inSecond > m.peak {
		m.peak = m.inSecond
	}

	line := m.summary(now)
	m.resetPeriod(now)

	return line
}

func (m *monitor) summary(now int64) string {
	var b strings.Builder

	b.WriteString("[FW] ")
	b.WriteString(m.name)
	fmt.Fprintf(&b, ": refused %d, allowed %d", m.refused, m.allowed)

	// Which layer let the rest through. "control port not protected" and
	// "default allow" look identical from a connection count and mean entirely
	// different things about the configuration.
	if top := dominant(m.allowedBy); top != "" {
		fmt.Fprintf(&b, " (%s)", top)
	}

	fmt.Fprintf(&b, " in %s | peak %d/s from %s",
		since(m.periodStart, now), m.peak, m.sourceCount())

	if by := breakdown(m.refusedBy); by != "" {
		b.WriteString(" | ")
		b.WriteString(by)
	}

	fmt.Fprintf(&b, " | total refused %d over %s", m.epRefused, since(m.episodeStart, now))

	return b.String()
}

func (m *monitor) sourceCount() string {
	if m.moreSources {
		return fmt.Sprintf("%d+ sources", maxReportedSources)
	}
	if len(m.sources) == 1 {
		for s := range m.sources {
			return s
		}
	}
	return fmt.Sprintf("%d sources", len(m.sources))
}

func (m *monitor) resetPeriod(now int64) {
	m.periodStart = now
	m.allowed, m.refused = 0, 0
	m.peak, m.inSecond = 0, 0
	m.named = 0
	clear(m.refusedBy)
	clear(m.allowedBy)
	clear(m.sources)
	m.moreSources = false
}

// breakdown renders the refusal reasons, busiest first, so the line names what
// is actually happening rather than only how much of it.
func breakdown(counts map[string]int64) string {
	if len(counts) == 0 {
		return ""
	}

	type entry struct {
		reason string
		n      int64
	}

	all := make([]entry, 0, len(counts))
	for reason, n := range counts {
		all = append(all, entry{reason, n})
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].n == all[j].n {
			return all[i].reason < all[j].reason
		}
		return all[i].n > all[j].n
	})

	parts := make([]string, 0, maxReportedReasons+1)
	var rest int64
	for i, e := range all {
		if i < maxReportedReasons {
			parts = append(parts, fmt.Sprintf("%s %d", e.reason, e.n))
			continue
		}
		rest += e.n
	}
	if rest > 0 {
		parts = append(parts, fmt.Sprintf("other %d", rest))
	}

	return strings.Join(parts, ", ")
}

// dominant is the most common key, named only when it is the whole story - a
// mix of reasons is what the refusal breakdown is for.
func dominant(counts map[string]int64) string {
	if len(counts) != 1 {
		return ""
	}
	for k := range counts {
		return k
	}
	return ""
}

func since(startMs, nowMs int64) string {
	d := max(nowMs-startMs, 0)
	if d < 10000 {
		return fmt.Sprintf("%.1fs", float64(d)/1000)
	}
	return fmt.Sprintf("%ds", d/1000)
}

// hostOf drops the port so two connections from one address count once.
func hostOf(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
