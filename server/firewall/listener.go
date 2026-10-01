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

	netpkg "github.com/fatedier/frp/pkg/util/net"
)

// guardedListener is a net.Listener that only yields connections the firewall
// has agreed to.
type guardedListener struct {
	net.Listener

	fw *Firewall
}

// GuardControl wraps ln so the firewall decides on every connection before the
// caller - or anything else - reads a byte from it.
//
// The ordering is the point. On the control port the raw socket is not handed
// to its accept loop directly: it goes to a protocol multiplexer first, which
// reads the opening bytes of every connection to tell websocket, tls and plain
// frp apart, waiting up to ten seconds for them. A check placed downstream of
// that lets a refused peer hold a goroutine and a buffer for the whole wait
// before it is asked anything.
//
// It is also the only place a refusal can be a reset. Once the multiplexer has
// wrapped the connection to replay the bytes it read, the socket underneath is
// out of reach and SetLinger cannot be asked for, so every rejection would fall
// back to a graceful close and leave frps holding a TIME_WAIT socket per peer
// it turned away.
//
// The decision is made inline in Accept: AllowControl never waits on anything
// slower than a map lookup - the reputation provider is asked in the background
// for this surface - so there is nothing to hand off to a goroutine.
func (f *Firewall) GuardControl(ln net.Listener) net.Listener {
	return &guardedListener{Listener: ln, fw: f}
}

func (g *guardedListener) Accept() (net.Conn, error) {
	for {
		c, err := g.Listener.Accept()
		if err != nil {
			return nil, err
		}

		remote := c.RemoteAddr().String()
		ok, reason := g.fw.AllowControl(remote, listenPort(c.LocalAddr()))
		// Both outcomes go to the monitor rather than to a log line of their
		// own: refusals alone cannot tell whether anything real is still
		// getting through.
		g.fw.NoteDecision(SurfaceControl, ok, reason, remote)
		if ok {
			return c, nil
		}
		refuse(c)
	}
}

// refuse turns a connection away with a reset rather than a graceful close.
//
// A rejected peer has no use for an orderly shutdown, and the four-way close
// would leave frps in TIME_WAIT for two maximum segment lifetimes per refusal.
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

// ListenPort is listenPort for the callers outside this package that decide a
// connection themselves - the quic listener, which has no net.Listener to wrap.
func ListenPort(addr net.Addr) int {
	return listenPort(addr)
}
