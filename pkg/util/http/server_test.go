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

package http

import (
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/fatedier/frp/pkg/util/guard"
)

// A refused peer must be dropped at the accept, not merely answered with a
// status: the point of the filter is that the connection never reaches the TLS
// handshake or the request parser above it.
func TestFilteredListenerDropsBeforeTheServerSeesIt(t *testing.T) {
	inner, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer inner.Close()

	var asked atomic.Int32
	admit := make(chan string, 1)
	ln := &filteredListener{Listener: inner, allow: func(remoteAddr string) bool {
		// Every second peer is turned away, so the test proves the loop keeps
		// going rather than stopping at the first rejection.
		return asked.Add(1)%2 == 0
	}}

	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			admit <- c.RemoteAddr().String()
			_ = c.Close()
		}
	}()

	// The refusal is a reset, and on loopback it can reach the client before
	// its own dial has finished - which is the refusal arriving, not a failure.
	rejected, err := net.Dial("tcp", inner.Addr().String())
	switch {
	case errors.Is(err, syscall.ECONNRESET):
		rejected = nil
	case err != nil:
		t.Fatal(err)
	default:
		defer rejected.Close()
	}

	allowed, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer allowed.Close()

	select {
	case got := <-admit:
		if got != allowed.LocalAddr().String() {
			t.Fatalf("Accept returned %s, want the admitted peer %s", got, allowed.LocalAddr())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the admitted peer never reached Accept")
	}

	// The refused one was closed by the listener, so reading from its end ends
	// straight away rather than waiting on a server that never heard of it.
	if rejected != nil {
		_ = rejected.SetReadDeadline(time.Now().Add(3 * time.Second))
		if _, err := rejected.Read(make([]byte, 1)); err == nil {
			t.Fatal("a refused connection should have been closed")
		}
	}
}

// The allow list goes first and the connection filter - the firewall - second,
// and a peer has to pass both. The filter is not even asked about somebody the
// list has already turned away.
func TestConnFilterRunsAfterTheAllowList(t *testing.T) {
	g, err := guard.New(guard.Config{AllowCIDRs: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}

	var asked []string
	s := &Server{guard: g}
	s.SetConnFilter(func(remoteAddr string) bool {
		asked = append(asked, remoteAddr)
		return remoteAddr != "10.0.0.2:1"
	})
	allow := s.admit()

	for _, tc := range []struct {
		addr string
		want bool
	}{
		{"10.0.0.1:1", true},   // on the list, filter agrees
		{"10.0.0.2:1", false},  // on the list, filter refuses
		{"192.0.2.1:1", false}, // off the list
		{"[2001:db8::1]:1", false},
	} {
		if got := allow(tc.addr); got != tc.want {
			t.Errorf("admit(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
	if len(asked) != 2 {
		t.Errorf("the filter was asked about %v; only peers on the allow list should reach it", asked)
	}
}

// Either check alone is used as is, and with neither there is nothing to wrap
// the listener in.
func TestAdmitWithOneOrNoChecks(t *testing.T) {
	if (&Server{}).admit() != nil {
		t.Error("a server with no allow list and no filter still wraps its listener")
	}

	s := &Server{}
	s.SetConnFilter(func(string) bool { return false })
	if allow := s.admit(); allow == nil || allow("192.0.2.1:1") {
		t.Error("a filter on its own was not applied")
	}

	g, err := guard.New(guard.Config{AllowCIDRs: []string{"10.0.0.0/8"}})
	if err != nil {
		t.Fatal(err)
	}
	if allow := (&Server{guard: g}).admit(); allow == nil || allow("192.0.2.1:1") || !allow("10.0.0.1:1") {
		t.Error("an allow list on its own was not applied")
	}
}
