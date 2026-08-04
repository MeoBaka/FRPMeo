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

//go:build !frps

package proxy

import (
	"net"
	"testing"
	"time"
)

// fakeConn is only ever asked for its remote address, which is all peerKey
// reads.
type fakeConn struct {
	net.Conn
	remote string
}

func (c *fakeConn) RemoteAddr() net.Addr { return fakeAddr(c.remote) }

type fakeAddr string

func (a fakeAddr) Network() string { return "tcp" }
func (a fakeAddr) String() string  { return string(a) }

func conn(remote string) net.Conn { return &fakeConn{remote: remote} }

// The bug this pins. A remote desktop session over xtcp+xudp takes the tcp and
// udp halves at once, and both are tagged streams over one visitor session. It
// was reported as two connections - three once the extra channel opened - while
// the same session over tcp+udp counted one, because only the relay path had a
// peer tracker.
func TestMergedP2PCountsOneVisitorOnce(t *testing.T) {
	m := newP2PMetrics("p", nil, true)

	tcp := conn("203.0.113.7:51000")
	m.tcpOpen(tcp)
	m.udpActivity(conn("203.0.113.7:51001"))

	if got := m.currentConns(); got != 1 {
		t.Fatalf("one visitor using both halves counted as %d, want 1", got)
	}

	// A second tcp stream from the same machine is still that machine.
	second := conn("203.0.113.7:51002")
	m.tcpOpen(second)
	if got := m.currentConns(); got != 1 {
		t.Fatalf("a second stream from one visitor counted as %d, want 1", got)
	}

	// A different visitor is a different peer.
	m.udpActivity(conn("198.51.100.4:40000"))
	if got := m.currentConns(); got != 2 {
		t.Fatalf("two visitors counted as %d, want 2", got)
	}

	m.tcpClose(tcp)
	m.tcpClose(second)
	if got := m.currentConns(); got != 2 {
		t.Fatalf("both visitors still have udp in flight, got %d want 2", got)
	}
}

// Plain xtcp and xudp carry one transport each, so they count the way a plain
// tcp proxy does - every stream on its own. Merging peers there would report
// one visitor holding four streams as a single connection.
func TestPlainP2PCountsEveryStream(t *testing.T) {
	m := newP2PMetrics("p", nil, false)

	a := conn("203.0.113.7:51000")
	b := conn("203.0.113.7:51001")
	m.tcpOpen(a)
	m.tcpOpen(b)

	if got := m.currentConns(); got != 2 {
		t.Fatalf("two streams counted as %d, want 2", got)
	}

	m.udpActivity(conn("203.0.113.7:51002"))
	if got := m.currentConns(); got != 3 {
		t.Fatalf("udp activity did not add its own count, got %d want 3", got)
	}

	m.tcpClose(a)
	m.tcpClose(b)
	if got := m.currentConns(); got != 1 {
		t.Fatalf("only the udp session should be left, got %d want 1", got)
	}
}

// A udp session that has gone quiet stops counting, and stops being remembered.
// The map must not grow with every visitor that ever sent a packet.
func TestIdleUDPPeersAreDropped(t *testing.T) {
	m := newP2PMetrics("p", nil, true)

	m.udpActivity(conn("203.0.113.7:51000"))
	if got := m.currentConns(); got != 1 {
		t.Fatalf("an active udp peer counted as %d, want 1", got)
	}

	// Age the record past the idle window.
	m.mu.Lock()
	for key := range m.udpByPeer {
		m.udpByPeer[key] = time.Now().Add(-2 * udpIdleTimeout).UnixNano()
	}
	m.mu.Unlock()

	if got := m.currentConns(); got != 0 {
		t.Fatalf("an idle udp peer still counted as %d, want 0", got)
	}

	m.mu.Lock()
	left := len(m.udpByPeer)
	m.mu.Unlock()
	if left != 0 {
		t.Errorf("%d idle peers left in the map; it would grow without bound", left)
	}
}

// Closing more times than opening must not leave a negative refcount behind,
// which would keep a peer counted forever.
func TestUnbalancedCloseDoesNotStrandAPeer(t *testing.T) {
	m := newP2PMetrics("p", nil, true)

	c := conn("203.0.113.7:51000")
	m.tcpOpen(c)
	m.tcpClose(c)
	m.tcpClose(c)

	if got := m.currentConns(); got != 0 {
		t.Fatalf("peer still counted as %d after closing, want 0", got)
	}
	m.mu.Lock()
	left := len(m.tcpByPeer)
	m.mu.Unlock()
	if left != 0 {
		t.Errorf("%d peers left in the tcp map", left)
	}
}
