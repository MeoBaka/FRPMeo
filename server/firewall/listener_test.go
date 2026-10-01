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
	"syscall"
	"testing"
	"time"

	gnet "github.com/fatedier/golib/net"

	netpkg "github.com/fatedier/frp/pkg/util/net"
)

// guarded starts a listener wrapped by f.GuardControl and drains whatever it
// admits, so the test can count admissions.
func guarded(t *testing.T, f *Firewall) (addr string, admitted <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	g := f.GuardControl(ln)
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

// dialRefused connects to addr and reports whether the server hung up on the
// connection rather than keeping it. The connection is never written to: the
// decision has to come before the first read, or a silent peer would be parked
// in the multiplexer instead of turned away.
//
// A refusal on loopback can arrive as a reset before the dial has finished, so
// a dial that fails with one counts as refused rather than failing the test.
func dialRefused(t *testing.T, addr string) bool {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		if errors.Is(err, syscall.ECONNRESET) {
			return true
		}
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()

	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = c.Read(make([]byte, 1))
	if err == nil {
		return false
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return false
	}
	return true
}

func controlFirewall(t *testing.T, rules []Rule) *Firewall {
	t.Helper()
	f := newTestFirewall(t, nil)
	if err := f.SetConfig(Config{
		Enabled: true, ControlPort: true, Default: "allow",
		Rules: rules, Provider: ProviderConfig{Mode: "off"},
	}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	return f
}

// A manual rule naming the control port is enforced at the listener, before a
// single byte is read from the peer.
func TestGuardControlAppliesRules(t *testing.T) {
	f := controlFirewall(t, []Rule{{ID: "r", Action: "deny", CIDR: "127.0.0.1", Port: "all"}})
	addr, admitted := guarded(t, f)

	if !dialRefused(t, addr) {
		t.Error("a deny rule covering the control port did not reject at the listener")
	}
	if n := len(admitted); n != 0 {
		t.Errorf("%d refused connections reached the caller", n)
	}
}

// A refusal must not end the accept loop: the next peer is decided on its own.
func TestGuardControlKeepsAcceptingAfterARefusal(t *testing.T) {
	deny := []Rule{{ID: "r", Action: "deny", CIDR: "127.0.0.1", Port: "all"}}
	f := controlFirewall(t, deny)
	addr, admitted := guarded(t, f)

	if !dialRefused(t, addr) {
		t.Fatal("the deny rule did not apply")
	}

	if err := f.SetConfig(Config{Enabled: true, ControlPort: true, Default: "allow", Provider: ProviderConfig{Mode: "off"}}); err != nil {
		t.Fatalf("set config: %v", err)
	}
	if dialRefused(t, addr) {
		t.Fatal("a peer was refused after the rule that refused the last one was removed")
	}
	select {
	case <-admitted:
	case <-time.After(5 * time.Second):
		t.Fatal("the allowed peer never reached the caller")
	}
}

// With nothing turned on the guard has to be invisible: it sits in front of
// every client connection, so a default install must not lose one.
func TestGuardControlPassesWhenNothingIsConfigured(t *testing.T) {
	f := newTestFirewall(t, nil)
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
			t.Fatalf("only %d of %d connections were admitted with nothing configured", got, want)
		}
	}
}

// The guard decides inline, so it must never wait on the provider - a slow one
// would otherwise hold up every client behind the one being looked up.
func TestGuardControlDoesNotWaitForTheProvider(t *testing.T) {
	p := newFakeProvider(t)
	p.delay.Store(int64(time.Second))
	f, _ := providerFirewall(t, p, providerOpts{controlPort: true, blocking: true})
	addr, admitted := guarded(t, f)

	start := time.Now()
	const want = 10
	for i := range want {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("dial %d: %v", i, err)
		}
		defer c.Close()
	}
	for got := range want {
		select {
		case <-admitted:
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d clients were admitted", got, want)
		}
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("admitting %d clients took %v behind a slow provider", want, elapsed)
	}
}

// Closing has to reach whoever is blocked in Accept, or shutdown hangs on the
// control port.
func TestGuardControlCloseUnblocksAccept(t *testing.T) {
	f := newTestFirewall(t, nil)
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

func TestListenPort(t *testing.T) {
	for _, tc := range []struct {
		addr net.Addr
		want int
	}{
		{&net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7000}, 7000},
		{&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 7001}, 7001},
		{nil, 0},
	} {
		if got := ListenPort(tc.addr); got != tc.want {
			t.Errorf("ListenPort(%v) = %d, want %d", tc.addr, got, tc.want)
		}
	}
}
