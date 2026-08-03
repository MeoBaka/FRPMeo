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
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"

	gnet "github.com/fatedier/golib/net"

	netpkg "github.com/fatedier/frp/pkg/util/net"
)

// guarded starts a listener wrapped by f.GuardControl and drains whatever it
// admits, so a connection that passes is not left waiting on the unbuffered
// handoff.
func guarded(t *testing.T, f *Firewall) (addr string, admitted <-chan net.Conn) {
	t.Helper()
	return guardedBy(t, f.GuardControl)
}

func guardedBy(t *testing.T, wrap func(net.Listener) net.Listener) (addr string, admitted <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	g := wrap(ln)
	t.Cleanup(func() { g.Close() })

	out := make(chan net.Conn, 64)
	go func() {
		for {
			c, err := g.Accept()
			if err != nil {
				close(out)
				return
			}
			out <- c
		}
	}()
	return g.Addr().String(), out
}

// refused reports whether the server hung up on c. An admitted connection is
// simply left open, so the two are told apart by whether a read returns
// anything at all before the deadline.
func refused(t *testing.T, c net.Conn) bool {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err := c.Read(make([]byte, 1))
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return true
}

// The flood this whole layer exists for: a peer that opens a socket and then
// says nothing. It used to be invisible - the check ran downstream of the
// protocol multiplexer, which parks a silent connection for its full read
// timeout and drops it there, having asked the firewall nothing. The decision
// has to happen before the first read, or it does not happen at all.
func TestGuardControlRefusesSilentPeers(t *testing.T) {
	const limit = 2

	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		Control: ControlProfile{Protect: true, RateProfile: RateProfile{
			WindowMs: 60000, MaxPerWindow: limit, BanViolations: maxInt,
		}},
	})
	addr, admitted := guarded(t, f)

	const attempts = 10
	got := 0
	for i := range attempts {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()

		// Deliberately never written to.
		if refused(t, c) {
			got++
		}
	}

	if want := attempts - limit; got != want {
		t.Errorf("silent peers refused = %d, want %d - the rate limit is not reached before the first read", got, want)
	}
	if n := len(admitted); n != limit {
		t.Errorf("admitted %d connections, want %d", n, limit)
	}
}

// A manual rule naming the control port is enforced at the listener too, not
// only the rate limit.
func TestGuardControlAppliesRules(t *testing.T) {
	f, err := New(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatalf("new firewall: %v", err)
	}
	if err := f.SetConfig(Config{
		Enabled: true, ControlPort: true, Default: "allow",
		Rules:    []Rule{{ID: "r", Action: "deny", CIDR: "127.0.0.1", Port: "all"}},
		Provider: ProviderConfig{Mode: "off"},
	}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	addr, _ := guarded(t, f)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if !refused(t, c) {
		t.Error("a deny rule covering the control port did not reject at the listener")
	}
}

// On a port frps shares with the vhost muxers, most of what arrives is a
// tunneled site's visitors. Charging them against the control profile - sized
// for how often a client reconnects - would throttle the site, so the rules
// half runs there alone.
func TestGuardControlRulesLeavesTheRateLimitAlone(t *testing.T) {
	f := newAAFirewall(t, AntiAttackerConfig{
		Enabled: true,
		Control: ControlProfile{Protect: true, RateProfile: RateProfile{
			WindowMs: 60000, MaxPerWindow: 2, BanViolations: maxInt,
		}},
	})
	addr, admitted := guardedBy(t, f.GuardControlRules)

	const want = 10
	for i := range want {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()
	}

	deadline := time.After(10 * time.Second)
	for got := range want {
		select {
		case _, ok := <-admitted:
			if !ok {
				t.Fatalf("the guard stopped after %d connections, want %d", got, want)
			}
		case <-deadline:
			t.Fatalf("only %d of %d visitors got through; the control rate limit is being applied on a shared port", got, want)
		}
	}
}

// And the other half, which goes on the listeners the multiplexer has already
// sorted: the rules ran once at accept and must not run again, or one address
// would be judged twice for one connection.
func TestGuardControlRateLeavesTheRulesAlone(t *testing.T) {
	f, err := New(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatalf("new firewall: %v", err)
	}
	if err := f.SetConfig(Config{
		Enabled: true, ControlPort: true, Default: "allow",
		Rules:    []Rule{{ID: "r", Action: "deny", CIDR: "127.0.0.1", Port: "all"}},
		Provider: ProviderConfig{Mode: "off"},
	}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	addr, _ := guardedBy(t, f.GuardControlRate)

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	if refused(t, c) {
		t.Error("the rate-limit half applied a rule, so a shared port judges one connection twice")
	}
}

// With nothing turned on the guard has to be invisible: it sits in front of
// every client connection, so a default install must not lose one.
func TestGuardControlPassesWhenNothingIsConfigured(t *testing.T) {
	f, err := New(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatalf("new firewall: %v", err)
	}
	addr, admitted := guarded(t, f)

	const want = 20
	for i := range want {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()
	}

	deadline := time.After(10 * time.Second)
	for got := range want {
		select {
		case _, ok := <-admitted:
			if !ok {
				t.Fatalf("the guard stopped after %d connections, want %d", got, want)
			}
		case <-deadline:
			t.Fatalf("only %d of %d connections were admitted with the firewall disabled", got, want)
		}
	}
}

// Closing has to reach whoever is blocked in Accept, or shutdown hangs on the
// control port.
func TestGuardControlCloseUnblocksAccept(t *testing.T) {
	f, err := New(filepath.Join(t.TempDir(), "fw.json"))
	if err != nil {
		t.Fatalf("new firewall: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	g := f.GuardControl(ln)

	done := make(chan error, 1)
	go func() {
		_, err := g.Accept()
		done <- err
	}()

	g.Close()

	select {
	case err := <-done:
		if err == nil {
			t.Error("Accept returned a connection after Close")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Accept did not return after Close")
	}
}

// Why the guard has to sit on the raw listener and not one connection later:
// the multiplexer wraps every connection to replay the bytes it read, and the
// wrapper exposes only net.Conn's own methods - no SetLinger, and nothing to
// unwrap back to the socket. A rejection made downstream of it can only be a
// graceful close, which leaves frps holding TIME_WAIT per refusal.
func TestResetIsOnlyReachableOnTheRawConnection(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err == nil {
			defer c.Close()
			time.Sleep(time.Second)
		}
	}()

	raw, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer raw.Close()

	if !netpkg.ArmReset(raw) {
		t.Fatal("a raw tcp connection cannot be reset, so refusals leak TIME_WAIT everywhere")
	}

	shared, _ := gnet.NewSharedConnSize(raw, 16)
	if netpkg.ArmReset(shared) {
		t.Skip("the multiplexer's wrapper now exposes the socket; the guard could move downstream")
	}
}
