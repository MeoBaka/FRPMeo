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

package secure

import (
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

const (
	testTitle = "dangnhap"
	testKey   = "secret123"
)

var visitor = netip.MustParseAddr("192.0.2.1")

// newTestGate builds a gate with the test title and key unless cfg sets its
// own, and a clock the test moves by hand.
func newTestGate(t *testing.T, cfg v1.SecureConfig, proxyType string) (*Gate, *time.Time) {
	t.Helper()
	cfg.Enable = true
	if cfg.Title == "" {
		cfg.Title = testTitle
	}
	if cfg.Key == "" {
		cfg.Key = testKey
	}
	g, err := NewGate("test-proxy", proxyType, &cfg)
	require.NoError(t, err)
	now := time.Unix(1_000_000, 0)
	g.now = func() time.Time { return now }
	return g, &now
}

func TestAllowListRefusesOutsidersEvenWithAKey(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{AllowIPs: []string{"10.0.0.0/8"}}, "tcp")

	require.Equal(t, refused, g.standingOf(visitor))
	require.Equal(t, unknown, g.standingOf(netip.MustParseAddr("10.1.2.3")),
		"inside the list a source still has to show the key")
}

func TestTrustedAddressesSkipTheKey(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{TrustedIPs: []string{"192.0.2.7", "198.51.100.0/24"}}, "tcp")

	require.Equal(t, admitted, g.standingOf(netip.MustParseAddr("192.0.2.7")))
	require.Equal(t, admitted, g.standingOf(netip.MustParseAddr("198.51.100.42")))
	require.Equal(t, unknown, g.standingOf(visitor))
}

func TestAnUnlockLastsForTheUnlockDuration(t *testing.T) {
	g, now := newTestGate(t, v1.SecureConfig{UnlockSeconds: 60}, "tcp")

	g.unlock(visitor)
	require.Equal(t, admitted, g.standingOf(visitor))

	*now = now.Add(61 * time.Second)
	require.Equal(t, unknown, g.standingOf(visitor))
}

func TestWrongKeysEarnABanThatRunsOut(t *testing.T) {
	g, now := newTestGate(t, v1.SecureConfig{AntiSpam: v1.SecureAntiSpamConfig{MaxFailures: 3, BanSeconds: 100}}, "tcp")

	g.noteFailure(visitor)
	g.noteFailure(visitor)
	require.Equal(t, unknown, g.standingOf(visitor))

	g.noteFailure(visitor)
	require.Equal(t, refused, g.standingOf(visitor))

	*now = now.Add(101 * time.Second)
	require.Equal(t, unknown, g.standingOf(visitor))
}

func TestOldWrongKeysAreForgotten(t *testing.T) {
	g, now := newTestGate(t, v1.SecureConfig{AntiSpam: v1.SecureAntiSpamConfig{MaxFailures: 2}}, "tcp")

	g.noteFailure(visitor)
	*now = now.Add(failureMemory + time.Minute)
	g.noteFailure(visitor)

	require.Equal(t, unknown, g.standingOf(visitor), "two failures an hour apart are not a guessing run")
}

func TestTooManyAttemptsInAMinuteEarnABan(t *testing.T) {
	g, now := newTestGate(t, v1.SecureConfig{AntiSpam: v1.SecureAntiSpamConfig{MaxAttemptsPerMinute: 2}}, "tcp")

	require.True(t, g.noteAttempt(visitor))
	require.True(t, g.noteAttempt(visitor))
	require.False(t, g.noteAttempt(visitor))
	require.Equal(t, refused, g.standingOf(visitor))

	*now = now.Add(time.Duration(v1.DefaultSecureBanSeconds+1) * time.Second)
	require.Equal(t, unknown, g.standingOf(visitor))
	require.True(t, g.noteAttempt(visitor), "a served ban starts a fresh window")
}

func TestAttemptsSpreadOverMinutesAreFine(t *testing.T) {
	g, now := newTestGate(t, v1.SecureConfig{AntiSpam: v1.SecureAntiSpamConfig{MaxAttemptsPerMinute: 2}}, "tcp")

	for range 10 {
		require.True(t, g.noteAttempt(visitor))
		*now = now.Add(31 * time.Second)
	}
}

func TestANegativeThresholdSwitchesTheCheckOff(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{AntiSpam: v1.SecureAntiSpamConfig{MaxFailures: -1, MaxAttemptsPerMinute: -1}}, "tcp")

	for range 100 {
		g.noteFailure(visitor)
		require.True(t, g.noteAttempt(visitor))
	}
	require.Equal(t, unknown, g.standingOf(visitor))
}

func TestAnUnlockForgivesEarlierMistakes(t *testing.T) {
	g, now := newTestGate(t, v1.SecureConfig{UnlockSeconds: 60, AntiSpam: v1.SecureAntiSpamConfig{MaxFailures: 2}}, "tcp")

	g.noteFailure(visitor)
	g.unlock(visitor)
	*now = now.Add(61 * time.Second)
	g.noteFailure(visitor)

	require.Equal(t, unknown, g.standingOf(visitor), "the failure before the unlock no longer counts")
}

func TestTheLineMethodOnlyWhereThereIsALine(t *testing.T) {
	for typ, want := range map[string]bool{"tcp": true, "udp": true, "tcpmux": true, "http": false, "https": false, "mc": false} {
		g, _ := newTestGate(t, v1.SecureConfig{}, typ)
		require.Equal(t, want, g.line, typ)
	}
}

func TestMethodsNarrowWhatIsTaken(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{Methods: []string{v1.SecureMethodLine}}, "tcp")

	require.False(t, g.TakesRequests())
	require.True(t, g.HasOtherWayIn())
}

func TestJudgeLine(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "tcp")

	require.Equal(t, keyGood, g.judgeLine([]byte("dangnhap: secret123\r\n")))
	require.Equal(t, keyGood, g.judgeLine([]byte("DangNhap:secret123")), "the title is not case-sensitive")
	require.Equal(t, keyWrong, g.judgeLine([]byte("dangnhap: secret1234\n")))
	require.Equal(t, keyAbsent, g.judgeLine([]byte("hello world\n")))
	require.Equal(t, keyAbsent, g.judgeLine([]byte("auth: secret123\n")), "another title is not a key at all")
}

func TestCookiesExpireAndBelongToOneKey(t *testing.T) {
	g, now := newTestGate(t, v1.SecureConfig{}, "http")
	v := g.cookieValue(now.Add(time.Hour))

	require.True(t, g.cookieValid(v))
	require.False(t, g.cookieValid(v+"x"), "a tampered cookie is refused")

	other, otherNow := newTestGate(t, v1.SecureConfig{Key: "another-key"}, "http")
	*otherNow = *now
	require.False(t, other.cookieValid(v), "changing the key logs everyone out")

	*now = now.Add(2 * time.Hour)
	require.False(t, g.cookieValid(v), "an expired cookie is refused")
}

func TestBadAddressListsAreErrors(t *testing.T) {
	_, err := NewGate("p", "tcp", &v1.SecureConfig{Enable: true, Title: testTitle, Key: testKey, TrustedIPs: []string{"not-an-ip"}})
	require.Error(t, err)
}

func TestHumanDuration(t *testing.T) {
	require.Equal(t, "12h", humanDuration(12*time.Hour))
	require.Equal(t, "1h30m", humanDuration(90*time.Minute))
	require.Equal(t, "45s", humanDuration(45*time.Second))
	require.Equal(t, "0s", humanDuration(0))
}
