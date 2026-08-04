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
	"strings"
	"testing"
)

// A server nobody is attacking writes nothing. The reports only exist to
// describe a flood, and a line every five seconds saying there is no flood is
// the same noise problem in a slower form.
func TestMonitorSaysNothingWhenQuiet(t *testing.T) {
	m := newMonitor("control 0.0.0.0:7000")

	for i := range 20 {
		if line := m.note(int64(i)*100, true, "default allow", "10.0.0.1:1"); line != "" {
			t.Fatalf("an admitted connection logged a line: %q", line)
		}
	}
	if line := m.tick(5000, false); line != "" {
		t.Errorf("a period with no refusals reported %q", line)
	}
}

// A trickle is named one refusal at a time. Holding them for a summary would
// make a denied client look like nothing happened, which is the case where
// somebody is staring at the log asking why they cannot connect.
func TestMonitorNamesEachRefusalWhileTheyAreFew(t *testing.T) {
	m := newMonitor("control 0.0.0.0:7000")

	line := m.note(1000, false, "rule r", "10.0.0.9:5555")
	if line == "" {
		t.Fatal("the first refusal was not logged")
	}
	for _, want := range []string{"10.0.0.9:5555", "rule r"} {
		if !strings.Contains(line, want) {
			t.Errorf("line %q does not mention %q", line, want)
		}
	}

	if again := m.note(1100, false, "rule r", "10.0.0.9:5556"); again == "" {
		t.Error("a second refusal was swallowed; while they are few, each one is named")
	}
}

// The production case this exists for: a reputation provider turning away one
// address every couple of minutes. That is not an attack, and reporting it as
// one - an opening line, a periodic line, then "attack over" - said three
// wrong things about a single refused connection.
func TestMonitorTrickleIsNotAnAttack(t *testing.T) {
	m := newMonitor("proxy")

	for i := range 3 {
		now := int64(i) * 120_000 // two minutes apart

		if line := m.note(now, false, "reputation", "203.0.113.7:1000"); line == "" {
			t.Fatalf("refusal %d was not named", i+1)
		}
		m.note(now+1, true, "default allow", "198.51.100.4:1")

		// Several report ticks pass with nothing sustained.
		for tick := range 3 {
			if line := m.tick(now+int64(tick+1)*5000, false); line != "" {
				t.Fatalf("a trickle produced %q; nothing here is an attack", line)
			}
		}
	}
}

// Past the budget the lines stop being information and become the flood, so
// the reporting switches to summaries - and that is when an episode opens.
func TestMonitorSwitchesToSummaryWhenRefusalsPileUp(t *testing.T) {
	m := newMonitor("proxy")

	named := 0
	for range maxNamedRefusals + 4 {
		if line := m.note(1000, false, "rate limit", "203.0.113.7:1000"); line != "" {
			named++
		}
	}
	if named != maxNamedRefusals {
		t.Fatalf("named %d refusals individually, want %d before switching", named, maxNamedRefusals)
	}

	line := m.tick(6000, false)
	if !strings.Contains(line, "refused 9") {
		t.Fatalf("summary did not count every refusal\ngot: %s", line)
	}

	// And it closes as refusals stopping, not as an attack, because none of
	// this ever raised the attack state.
	closing := m.tick(11000, false)
	if !strings.Contains(closing, "refusals stopped") {
		t.Errorf("closing line calls it an attack when nothing was under attack\ngot: %s", closing)
	}
}

// What the periodic line has to carry: how much, from how many, why, how hard
// at its worst, and whether anything real is still getting through.
func TestMonitorPeriodicLineCarriesTheNumbers(t *testing.T) {
	m := newMonitor("control 0.0.0.0:7000")

	m.note(1000, false, "rate limit", "10.0.0.1:1")
	for i := range 40 {
		m.note(1000, false, "rate limit", fmt.Sprintf("10.0.0.%d:1", i))
	}
	for i := range 3 {
		m.note(2000, false, "struck (not a client)", fmt.Sprintf("10.0.1.%d:1", i))
	}
	m.note(2000, true, "default allow", "10.0.9.9:1")

	line := m.tick(6000, true)
	if line == "" {
		t.Fatal("a period full of refusals reported nothing")
	}

	for _, want := range []string{
		"UNDER ATTACK",
		"refused 44",
		"allowed 1",
		"default allow",
		"rate limit 41",
		"struck (not a client) 3",
		"peak 41/s",
		"sources",
		"total refused 44",
	} {
		if !strings.Contains(line, want) {
			t.Errorf("periodic line is missing %q\ngot: %s", want, line)
		}
	}
}

// Totals accumulate across periods, so the line answers "how much altogether"
// and not only "how much in the last five seconds".
func TestMonitorTotalsSpanTheEpisode(t *testing.T) {
	m := newMonitor("control 0.0.0.0:7000")

	m.note(0, false, "rate limit", "10.0.0.1:1")
	m.tick(5000, true)

	for range 9 {
		m.note(6000, false, "rate limit", "10.0.0.1:1")
	}

	line := m.tick(10000, true)
	if !strings.Contains(line, "total refused 10") {
		t.Errorf("totals did not carry across periods\ngot: %s", line)
	}
}

// And the episode ends on its own, so the log says when it was over rather than
// leaving the reader to notice that the lines stopped.
func TestMonitorClosesTheEpisode(t *testing.T) {
	m := newMonitor("control 0.0.0.0:7000")

	m.note(0, false, "rate limit", "10.0.0.1:1")
	m.tick(5000, true)

	line := m.tick(10000, false)
	if !strings.Contains(line, "attack over") {
		t.Fatalf("a period with no refusals did not close the episode\ngot: %q", line)
	}
	if !strings.Contains(line, "refused 1") {
		t.Errorf("the closing line does not total the episode\ngot: %s", line)
	}

	if again := m.tick(15000, false); again != "" {
		t.Errorf("the episode closed twice: %q", again)
	}
}

// The attack state is judged across every surface at once, so it can come up
// before this listener has refused anything - and that is worth a line, since
// it is when the shortened handshake timeout takes effect.
func TestMonitorReportsAttackStateWithoutRefusals(t *testing.T) {
	m := newMonitor("control 0.0.0.0:7000")

	m.note(1000, true, "default allow", "10.0.0.1:1")

	line := m.tick(5000, true)
	if !strings.Contains(line, "UNDER ATTACK") {
		t.Errorf("the attack state was not reported\ngot: %q", line)
	}
}

// A source set that grows with the flood is the flood winning a second time.
func TestMonitorSourceCountSaturates(t *testing.T) {
	m := newMonitor("control 0.0.0.0:7000")

	for i := range maxReportedSources + 500 {
		m.note(1000, false, "rate limit", fmt.Sprintf("10.%d.%d.%d:1", i/65536, (i/256)%256, i%256))
	}

	if n := len(m.sources); n > maxReportedSources {
		t.Errorf("tracked %d sources, cap is %d", n, maxReportedSources)
	}
	if line := m.tick(6000, true); !strings.Contains(line, fmt.Sprintf("%d+ sources", maxReportedSources)) {
		t.Errorf("a saturated source set is not reported as such\ngot: %s", line)
	}
}

// One source is worth naming; a thousand are worth counting.
func TestMonitorNamesASingleSource(t *testing.T) {
	m := newMonitor("control 0.0.0.0:7000")

	// Past the naming budget, so a summary is produced at all.
	for i := range maxNamedRefusals + 3 {
		m.note(1000, false, "rate limit", fmt.Sprintf("10.0.0.7:%d", 1000+i))
	}

	if line := m.tick(6000, false); !strings.Contains(line, "from 10.0.0.7") {
		t.Errorf("a lone source was not named\ngot: %s", line)
	}
}

func TestBreakdownOrdersByCountAndCapsTheTail(t *testing.T) {
	counts := map[string]int64{"a": 1, "b": 50, "c": 7, "d": 2, "e": 3, "f": 4, "g": 9}

	got := breakdown(counts)
	want := "b 50, g 9, c 7, f 4, e 3, other 3"
	if got != want {
		t.Errorf("breakdown = %q, want %q", got, want)
	}
}
