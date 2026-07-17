// Copyright 2026 fatedier, fatedier@gmail.com
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

package proxy

import (
	"net"
	"sync"
)

// peerTracker counts distinct peer IPs instead of individual connections.
//
// A tcp+udp proxy serves one peer over two transports that are counted in
// unrelated places: the TCP half counts every accepted connection, the UDP half
// counts every distinct source address. A player using both would therefore be
// reported twice. Routing both halves through one tracker keyed by IP reports
// them as the single peer they are.
//
// The counter only moves at the edges: onOpen when an IP's first use arrives,
// onClose when its last one goes away. So a peer holding several TCP
// connections plus a UDP session still counts once.
type peerTracker struct {
	mu      sync.Mutex
	refs    map[string]int
	onOpen  func()
	onClose func()
}

func newPeerTracker(onOpen, onClose func()) *peerTracker {
	return &peerTracker{
		refs:    make(map[string]int),
		onOpen:  onOpen,
		onClose: onClose,
	}
}

// acquire registers one use of remoteAddr's peer.
func (t *peerTracker) acquire(remoteAddr string) {
	ip := peerIP(remoteAddr)
	t.mu.Lock()
	t.refs[ip]++
	first := t.refs[ip] == 1
	t.mu.Unlock()
	if first {
		t.onOpen()
	}
}

// release drops one use of remoteAddr's peer. Releasing an address that was
// never acquired is a no-op, so callers need not track that themselves.
func (t *peerTracker) release(remoteAddr string) {
	ip := peerIP(remoteAddr)
	t.mu.Lock()
	n, ok := t.refs[ip]
	if !ok {
		t.mu.Unlock()
		return
	}
	n--
	last := n <= 0
	if last {
		delete(t.refs, ip)
	} else {
		t.refs[ip] = n
	}
	t.mu.Unlock()
	if last {
		t.onClose()
	}
}

// peerIP reduces an address to the peer it identifies. The port is what makes
// two connections from one machine distinct, so dropping it is the whole point.
func peerIP(remoteAddr string) string {
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		return host
	}
	return remoteAddr
}
