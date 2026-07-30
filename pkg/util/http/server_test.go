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
	"net"
	"sync/atomic"
	"testing"
	"time"
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

	rejected, err := net.Dial("tcp", inner.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer rejected.Close()

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
	_ = rejected.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := rejected.Read(make([]byte, 1)); err == nil {
		t.Fatal("a refused connection should have been closed")
	}
}
