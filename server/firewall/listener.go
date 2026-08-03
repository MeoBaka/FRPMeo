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
	"net"
	"strconv"
	"sync"

	netpkg "github.com/fatedier/frp/pkg/util/net"
)

// maxPendingAdmissions bounds how many connections may be waiting on a firewall
// decision at once.
//
// The decision is usually a handful of map lookups, but not always: with a
// blocking reputation provider configured it is an http round trip. Running
// that inline in the accept loop would let one slow lookup hold up every other
// client, so admissions run concurrently - and the bound is what stops that
// from becoming one goroutine per connection under a flood.
//
// At the limit connections are refused outright rather than queued. Turning
// somebody away quickly is the better answer when the work behind the queue is
// already not keeping up.
const maxPendingAdmissions = 2048

// guardedListener is a net.Listener that only yields connections the firewall
// has agreed to.
type guardedListener struct {
	net.Listener

	fw *Firewall

	// rules and rate select which halves of the control decision run here. They
	// are separable because a port shared with vhost traffic can only have one
	// of them applied at accept - see GuardControlRules.
	rules bool
	rate  bool

	// admitted carries the connections that passed. Unbuffered on purpose:
	// whoever reads this listener accepts in a tight loop, so it is always
	// ready, and a buffer would only be somewhere for admitted connections to
	// sit unattended.
	admitted chan net.Conn

	// done is closed once the listener is finished, by Close or by the
	// underlying Accept failing. err is written before it closes, so anything
	// that reads err after receiving from done sees the final value.
	done chan struct{}
	once sync.Once
	err  error
}

// GuardControl wraps ln so the firewall decides on every connection before the
// caller - or anything else - reads a byte from it.
//
// This ordering is the whole point, not a detail. On the control port the raw
// socket is not handed to its accept loop directly: it goes to a protocol
// multiplexer first, which reads the opening bytes of every connection to tell
// websocket, tls and plain frp apart and only passes it on once it has them.
// That read waits up to ten seconds, on a goroutine the multiplexer spawns per
// connection without a bound.
//
// A firewall placed downstream of that never sees the connections worth
// stopping. A peer that opens a socket and then sends fewer bytes than the
// longest matcher needs is parked in the multiplexer for the whole timeout and
// dropped there - having cost a goroutine, a descriptor and a buffer, and
// having been asked nothing. That is the cheapest flood there is, and it is
// exactly what the anti-attack layer exists for.
//
// It is also the only place a refusal can be a reset. Once the multiplexer has
// wrapped the connection to replay the bytes it read, the socket underneath is
// out of reach and SetLinger cannot be asked for, so every rejection would fall
// back to a graceful close and leave frps holding TIME_WAIT - kernel state
// proportional to the attack, accumulating on the side doing the refusing.
//
// Decisions are made in the same order as everywhere else: manual rules and
// reputation first, then the rate limit.
//
// For a listener that carries client control traffic and nothing else.
func (f *Firewall) GuardControl(ln net.Listener) net.Listener {
	return f.guard(ln, true, true)
}

// GuardControlRules installs only the first half of GuardControl's decision:
// the manual rules and the reputation provider, which judge an address and so
// are right for any traffic that arrives.
//
// For a port frps shares between client control traffic and the vhost muxers.
// There, visitors to a tunneled site land on the same socket as frpc, and
// which of the two a connection is cannot be known until the multiplexer has
// read its opening bytes. Charging a website's visitors against the control
// profile - a limit sized for how often a client reconnects - would throttle
// the site, so the rate limit waits until the protocol is known and goes on the
// control listeners the multiplexer produces, via GuardControlRate.
//
// The cheapest flood is not stopped as early on such a port. That is the cost
// of the configuration rather than of this: a decision that depends on reading
// the connection cannot be made before it.
func (f *Firewall) GuardControlRules(ln net.Listener) net.Listener {
	return f.guard(ln, true, false)
}

// GuardControlRate installs only the second half: the control rate limit.
//
// The other side of the split GuardControlRules describes - it goes on the
// listeners a multiplexer has already sorted, where the traffic is known to be
// a client rather than a visitor.
func (f *Firewall) GuardControlRate(ln net.Listener) net.Listener {
	return f.guard(ln, false, true)
}

func (f *Firewall) guard(ln net.Listener, rules, rate bool) net.Listener {
	g := &guardedListener{
		Listener: ln,
		fw:       f,
		rules:    rules,
		rate:     rate,
		admitted: make(chan net.Conn),
		done:     make(chan struct{}),
	}
	go g.serve()
	return g
}

// serve is the real accept loop. It never blocks on a decision, so a flood is
// refused at the speed connections arrive rather than at the speed they can be
// judged.
func (g *guardedListener) serve() {
	pending := make(chan struct{}, maxPendingAdmissions)
	for {
		c, err := g.Listener.Accept()
		if err != nil {
			g.finish(err)
			return
		}

		select {
		case pending <- struct{}{}:
		default:
			// Every admission slot is busy. Refuse rather than wait: the accept
			// loop staying responsive is the whole point of the bound.
			g.noteDecision(false, "admission queue full", c.RemoteAddr().String())

			refuse(c)
			continue
		}

		go func(c net.Conn) {
			defer func() { <-pending }()

			if !g.decide(c) {
				refuse(c)
				return
			}

			select {
			case g.admitted <- c:
			case <-g.done:
				c.Close()
			}
		}(c)
	}
}

// decide runs the firewall over one connection and reports whether it may stay.
//
// Both outcomes go to the monitor rather than to a log line of their own. Every
// decision is counted either way: refusals alone cannot tell a flood being
// absorbed from a flood that never arrived, and admissions alone cannot tell an
// open door from a quiet night. Together they can, which is why the periodic
// line carries both.
func (g *guardedListener) decide(c net.Conn) bool {
	remote := c.RemoteAddr().String()

	// Set by the rules half, or naming its absence: on a shared port the rules
	// ran at accept and only the rate limit is left here.
	verdict := "rules applied upstream"

	if g.rules {
		ok, reason := g.fw.AllowControl(remote, listenPort(c.LocalAddr()))
		if !ok {
			g.noteDecision(false, reason, remote)
			return false
		}
		verdict = reason
	}

	// Rate limit after the rules, matching the order on the proxy paths.
	if g.rate {
		if v := g.fw.AdmitControl(remote); !v.Allowed {
			g.noteDecision(false, v.Reason, remote)
			return false
		}
	}

	g.noteDecision(true, verdict, remote)

	return true
}

func (g *guardedListener) noteDecision(allowed bool, reason, remote string) {
	g.fw.NoteDecision(SurfaceControl, allowed, reason, remote)
}

func (g *guardedListener) Accept() (net.Conn, error) {
	select {
	case c := <-g.admitted:
		return c, nil
	case <-g.done:
		return nil, g.err
	}
}

func (g *guardedListener) Close() error {
	// Recorded before the underlying close so the accept loop's own error - a
	// use-of-closed-connection that says nothing - does not become what callers
	// are told.
	g.finish(net.ErrClosed)
	return g.Listener.Close()
}

func (g *guardedListener) finish(err error) {
	g.once.Do(func() {
		g.err = err
		close(g.done)
	})
}

// refuse turns a connection away with a reset rather than a graceful close.
//
// A rejected peer has no use for an orderly shutdown, and the four-way close
// would leave frps in TIME_WAIT for two maximum segment lifetimes per refusal.
// That is kernel state proportional to the attack, held by the side doing the
// refusing, which is the wrong way round.
func refuse(c net.Conn) {
	netpkg.ArmReset(c)
	c.Close()
}

// listenPort is the port a connection landed on, which is what a firewall rule
// names. Returns 0 when the address carries no port.
func listenPort(addr net.Addr) int {
	if addr == nil {
		return 0
	}
	switch a := addr.(type) {
	case *net.TCPAddr:
		return a.Port
	case *net.UDPAddr:
		return a.Port
	}
	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}
	return n
}
