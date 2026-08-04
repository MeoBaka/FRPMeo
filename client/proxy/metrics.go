// Copyright 2025 The frp Authors
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
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/transport"
)

// udpIdleTimeout is how long after the last real UDP packet a P2P UDP tunnel is
// still counted as an active session. A P2P UDP stream is kept alive by heartbeat
// pings, so without this it would be reported as "1 connection" forever; instead
// it drops to 0 shortly after the app stops sending UDP.
const udpIdleTimeout = 15 * time.Second

// p2pMetrics measures a provider proxy's P2P tunnel — byte counters plus a
// session count — and periodically reports the delta to frps, which cannot
// observe P2P data itself (it bypasses frps through the punched hole). Session
// counting is split by transport: TCP streams are counted precisely while open
// (libio.Join returns exactly on close), while the single persistent UDP stream
// is counted only while UDP packets are recently flowing. Only the P2P path is
// reported; the relay-fallback path is measured by frps, so the two never double
// count.
type p2pMetrics struct {
	// name is the wire proxy name (with user prefix) exactly as frps keys it.
	name string
	mt   transport.MessageTransporter

	// mergePeers makes a peer using both halves count once rather than twice.
	//
	// Only the merged proxy type sets it. On xtcp+xudp the two halves are
	// tagged streams over one visitor session, so a remote desktop - which
	// takes tcp and udp at the same time - is one visitor, not two. Plain xtcp
	// and xudp carry one transport each and count the way a plain tcp proxy
	// does. This is the same rule the relay path applies in server/proxy's
	// peerTracker; the two paths disagreeing is what made one visitor read as
	// two or three on the dashboard.
	mergePeers bool

	mu sync.Mutex
	// tcpByPeer counts open TCP streams per peer, udpByPeer holds the unix-nano
	// of each peer's last real UDP packet. Keyed by address without the port,
	// because the port is what makes two connections from one machine look
	// like two peers.
	tcpByPeer map[string]int
	udpByPeer map[string]int64

	tcpTotal atomic.Int64 // active TCP streams, for the un-merged count
	in       atomic.Int64 // cumulative bytes read from the tunnel
	out      atomic.Int64 // cumulative bytes written to the tunnel

	lastConns int64
	lastIn    int64
	lastOut   int64

	started atomic.Bool
}

func newP2PMetrics(name string, mt transport.MessageTransporter, mergePeers bool) *p2pMetrics {
	return &p2pMetrics{
		name:       name,
		mt:         mt,
		mergePeers: mergePeers,
		tcpByPeer:  make(map[string]int),
		udpByPeer:  make(map[string]int64),
	}
}

// peerKey reduces a connection to the peer behind it. Dropping the port is the
// whole point: one machine opening two streams is one peer.
func peerKey(c net.Conn) string {
	if c == nil {
		return ""
	}
	addr := c.RemoteAddr()
	if addr == nil {
		return ""
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

// countBytes wraps a tunnel stream so its bytes are counted. It does NOT count a
// session — session counting is done per-transport (tcpOpen/tcpClose for TCP,
// udpActivity for UDP).
func (m *p2pMetrics) countBytes(c net.Conn) net.Conn {
	if m == nil {
		return c
	}
	return &byteCountConn{Conn: c, m: m}
}

func (m *p2pMetrics) tcpOpen(c net.Conn) {
	if m == nil {
		return
	}
	m.tcpTotal.Add(1)

	m.mu.Lock()
	m.tcpByPeer[peerKey(c)]++
	m.mu.Unlock()
}

func (m *p2pMetrics) tcpClose(c net.Conn) {
	if m == nil {
		return
	}
	m.tcpTotal.Add(-1)

	key := peerKey(c)
	m.mu.Lock()
	if n := m.tcpByPeer[key] - 1; n > 0 {
		m.tcpByPeer[key] = n
	} else {
		delete(m.tcpByPeer, key)
	}
	m.mu.Unlock()
}

// udpActivity records that a real UDP packet just flowed on the tunnel.
func (m *p2pMetrics) udpActivity(c net.Conn) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.udpByPeer[peerKey(c)] = time.Now().UnixNano()
	m.mu.Unlock()
}

// currentConns is what gets reported to frps.
//
// Merged: the number of distinct peers using either half. Otherwise: TCP
// streams plus 1 if UDP has been active within udpIdleTimeout, which is what a
// single-transport proxy has always reported.
func (m *p2pMetrics) currentConns() int64 {
	cutoff := time.Now().Add(-udpIdleTimeout).UnixNano()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Idle udp peers are dropped here rather than on a timer: this runs on the
	// report tick, and a peer with nothing recent is exactly what the map must
	// not keep growing with.
	udpActive := false
	for key, last := range m.udpByPeer {
		if last < cutoff {
			delete(m.udpByPeer, key)
			continue
		}
		udpActive = true
	}

	if !m.mergePeers {
		c := m.tcpTotal.Load()
		if udpActive {
			c++
		}
		return c
	}

	peers := make(map[string]struct{}, len(m.tcpByPeer)+len(m.udpByPeer))
	for key := range m.tcpByPeer {
		peers[key] = struct{}{}
	}
	for key := range m.udpByPeer {
		peers[key] = struct{}{}
	}
	return int64(len(peers))
}

// startReporter launches the periodic delta reporter once (idempotent). It stops
// when ctx is done after a final flush that zeroes the reported connection count.
func (m *p2pMetrics) startReporter(ctx context.Context) {
	if m == nil || m.mt == nil {
		return
	}
	if !m.started.CompareAndSwap(false, true) {
		return
	}
	go func() {
		// Report every 10s. flush() is a no-op when nothing moved, so idle
		// proxies stay silent and the message itself is tiny.
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				// Final report: force our reported connections to 0 so frps does
				// not keep a stale value on graceful shutdown.
				m.tcpTotal.Store(0)
				m.mu.Lock()
				clear(m.tcpByPeer)
				clear(m.udpByPeer)
				m.mu.Unlock()
				m.flush()
				return
			case <-ticker.C:
				m.flush()
			}
		}
	}()
}

// flush sends the change since the last report; it is a no-op when nothing moved.
func (m *p2pMetrics) flush() {
	conns := m.currentConns()
	in := m.in.Load()
	out := m.out.Load()
	dConns := conns - m.lastConns
	dIn := in - m.lastIn
	dOut := out - m.lastOut
	if dConns == 0 && dIn == 0 && dOut == 0 {
		return
	}
	m.lastConns, m.lastIn, m.lastOut = conns, in, out
	_ = m.mt.Send(&msg.ProxyMetrics{
		ProxyName:       m.name,
		ConnsDelta:      dConns,
		TrafficInDelta:  dIn,
		TrafficOutDelta: dOut,
	})
}

type byteCountConn struct {
	net.Conn
	m *p2pMetrics
}

func (c *byteCountConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if n > 0 {
		c.m.in.Add(int64(n))
	}
	return n, err
}

func (c *byteCountConn) Write(b []byte) (int, error) {
	n, err := c.Conn.Write(b)
	if n > 0 {
		c.m.out.Add(int64(n))
	}
	return n, err
}
