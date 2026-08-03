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

package net

import (
	"errors"
	"io"
	"net"
	"testing"
)

// readAll drains c until it errors, and reports how much came out and why it
// stopped.
func readAll(c net.Conn) (int, error) {
	buf := make([]byte, 4096)
	total := 0
	for {
		n, err := c.Read(buf)
		total += n
		if err != nil {
			return total, err
		}
	}
}

// feed writes payload to one end of a pipe and returns the other, so a test can
// read from a real net.Conn.
func feed(t *testing.T, payload []byte) net.Conn {
	t.Helper()
	server, client := net.Pipe()
	go func() {
		_, _ = client.Write(payload)
		client.Close()
	}()
	t.Cleanup(func() { server.Close() })
	return server
}

// The case this exists for: a peer that opens a connection and pushes far more
// than any handshake needs. It breaks no rate - one connection is one
// connection - so only a byte ceiling sees it.
func TestLimitHandshakeStopsAnOversizedPeer(t *testing.T) {
	c, _ := LimitHandshake(feed(t, make([]byte, 64*1024)), 4096)

	n, err := readAll(c)
	if !errors.Is(err, ErrHandshakeTooLarge) {
		t.Fatalf("read stopped with %v after %d bytes, want ErrHandshakeTooLarge", err, n)
	}
	if n > 4096+4096 {
		t.Errorf("read %d bytes past a 4096 limit; the cap is not being applied per read", n)
	}
}

// A real client sends a few hundred bytes and must not notice the limit.
func TestLimitHandshakeLetsAnOrdinaryHandshakeThrough(t *testing.T) {
	c, _ := LimitHandshake(feed(t, make([]byte, 600)), 4096)

	n, err := readAll(c)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("read stopped with %v, want a clean EOF", err)
	}
	if n != 600 {
		t.Errorf("read %d bytes, want 600", n)
	}
}

// Once the peer has identified itself the bytes belong to the tunnel, and a
// tunnel carries far more than any handshake ceiling.
func TestLimitHandshakeStopsCountingAfterTheHandshake(t *testing.T) {
	c, done := LimitHandshake(feed(t, make([]byte, 64*1024)), 4096)
	done()

	n, err := readAll(c)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("read stopped with %v after %d bytes; the lifted cap is still counting", err, n)
	}
	if n != 64*1024 {
		t.Errorf("read %d bytes, want the whole 65536", n)
	}
}

// Zero means no limit, so callers need not branch on whether it is configured.
func TestLimitHandshakeOffReturnsTheConnUnchanged(t *testing.T) {
	raw := feed(t, make([]byte, 32*1024))

	c, done := LimitHandshake(raw, 0)
	if c != raw {
		t.Error("a zero limit still wrapped the connection")
	}
	done() // must be safe to call

	if n, err := readAll(c); !errors.Is(err, io.EOF) {
		t.Fatalf("read stopped with %v after %d bytes", err, n)
	}
}

// The socket underneath has to stay reachable, or a refusal cannot be a reset.
func TestLimitHandshakeKeepsResetReachable(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	go func() {
		if c, err := net.Dial("tcp", ln.Addr().String()); err == nil {
			defer c.Close()
			select {}
		}
	}()

	raw, err := ln.Accept()
	if err != nil {
		t.Fatalf("accept: %v", err)
	}
	defer raw.Close()

	limited, _ := LimitHandshake(raw, 4096)
	if !ArmReset(limited) {
		t.Fatal("the wrapper hides the socket, so rejections would leak TIME_WAIT")
	}
}
