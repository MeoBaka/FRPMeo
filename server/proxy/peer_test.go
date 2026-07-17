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
	"sync"
	"sync/atomic"
	"testing"
)

func newCountingPeerTracker() (*peerTracker, *int64) {
	var open int64
	t := newPeerTracker(
		func() { atomic.AddInt64(&open, 1) },
		func() { atomic.AddInt64(&open, -1) },
	)
	return t, &open
}

// The reason this type exists: one peer on both halves of a tcp+udp proxy is
// one connection, not two.
func TestPeerTrackerCountsTCPAndUDPPeerOnce(t *testing.T) {
	tracker, open := newCountingPeerTracker()

	tracker.acquire("10.0.0.1:51000") // tcp
	tracker.acquire("10.0.0.1:51001") // udp session, same peer
	if got := atomic.LoadInt64(open); got != 1 {
		t.Fatalf("one peer over two transports should count once, got %d", got)
	}

	tracker.release("10.0.0.1:51000")
	if got := atomic.LoadInt64(open); got != 1 {
		t.Fatalf("peer still has its udp session, want 1 got %d", got)
	}

	tracker.release("10.0.0.1:51001")
	if got := atomic.LoadInt64(open); got != 0 {
		t.Fatalf("peer fully gone, want 0 got %d", got)
	}
}

func TestPeerTrackerCountsDistinctPeersSeparately(t *testing.T) {
	tracker, open := newCountingPeerTracker()

	tracker.acquire("10.0.0.1:1000")
	tracker.acquire("10.0.0.2:1000")
	tracker.acquire("[2001:db8::1]:1000")
	if got := atomic.LoadInt64(open); got != 3 {
		t.Fatalf("three peers, want 3 got %d", got)
	}

	tracker.release("10.0.0.2:1000")
	if got := atomic.LoadInt64(open); got != 2 {
		t.Fatalf("want 2 got %d", got)
	}
}

// Several connections from one machine are still one peer.
func TestPeerTrackerRefcountsSamePeer(t *testing.T) {
	tracker, open := newCountingPeerTracker()

	for _, addr := range []string{"10.0.0.1:1", "10.0.0.1:2", "10.0.0.1:3"} {
		tracker.acquire(addr)
	}
	if got := atomic.LoadInt64(open); got != 1 {
		t.Fatalf("want 1 got %d", got)
	}

	tracker.release("10.0.0.1:1")
	tracker.release("10.0.0.1:2")
	if got := atomic.LoadInt64(open); got != 1 {
		t.Fatalf("one connection left, want 1 got %d", got)
	}
	tracker.release("10.0.0.1:3")
	if got := atomic.LoadInt64(open); got != 0 {
		t.Fatalf("want 0 got %d", got)
	}
	if len(tracker.refs) != 0 {
		t.Fatalf("refs must not retain departed peers: %v", tracker.refs)
	}
}

// The udp janitor and the tcp handler can both report the same session gone.
func TestPeerTrackerReleaseUnknownIsNoop(t *testing.T) {
	tracker, open := newCountingPeerTracker()

	tracker.release("10.0.0.9:1")
	if got := atomic.LoadInt64(open); got != 0 {
		t.Fatalf("releasing an unknown peer must not go negative, got %d", got)
	}

	tracker.acquire("10.0.0.1:1")
	tracker.release("10.0.0.1:1")
	tracker.release("10.0.0.1:1") // double release
	if got := atomic.LoadInt64(open); got != 0 {
		t.Fatalf("want 0 got %d", got)
	}
}

func TestPeerTrackerConcurrent(t *testing.T) {
	tracker, open := newCountingPeerTracker()

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			addr := "10.0.0.1:" + string(rune('a'+i%26))
			tracker.acquire(addr)
			tracker.release(addr)
		})
	}
	wg.Wait()

	if got := atomic.LoadInt64(open); got != 0 {
		t.Fatalf("balanced acquire/release must end at 0, got %d", got)
	}
	if len(tracker.refs) != 0 {
		t.Fatalf("refs leaked: %v", tracker.refs)
	}
}

func TestPeerIP(t *testing.T) {
	for addr, want := range map[string]string{
		"10.0.0.1:51000":      "10.0.0.1",
		"[2001:db8::1]:51000": "2001:db8::1",
		"10.0.0.1":            "10.0.0.1", // no port: already a bare peer
	} {
		if got := peerIP(addr); got != want {
			t.Fatalf("peerIP(%q) = %q, want %q", addr, got, want)
		}
	}
}
