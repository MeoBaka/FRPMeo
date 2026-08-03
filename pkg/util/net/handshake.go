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
	"net"
	"sync/atomic"
)

// ErrHandshakeTooLarge is returned by a read that would take a peer past the
// limit set with LimitHandshake.
var ErrHandshakeTooLarge = errors.New("peer sent too much before finishing the handshake")

// LimitHandshake caps how much may be read from c before Disarm is called, and
// returns the wrapped connection with the function that lifts the cap.
//
// The connection counters cannot see this: one connection is one connection
// however many megabytes it carries, so a peer that opens a socket and pushes
// data without ever identifying itself breaks no rate at all. What it does
// break is memory, which is the resource a handshake holds while it waits.
//
// Reads are counted rather than individual buffer sizes, because in Go the
// caller picks the buffer and "how much arrived at once" is not a thing the
// peer decides. Total consumed before the handshake finishes is the meaningful
// figure anyway: it is exactly what the peer chose to send.
//
// A limit of zero or less returns c unchanged, so callers need not branch.
func LimitHandshake(c net.Conn, limit int) (net.Conn, func()) {
	if limit <= 0 {
		return c, func() {}
	}
	lc := &handshakeLimitedConn{Conn: c, limit: int64(limit)}
	return lc, func() { lc.done.Store(true) }
}

type handshakeLimitedConn struct {
	net.Conn

	limit int64
	read  atomic.Int64
	// done is the zero value until the handshake finishes, so the limit is in
	// force from the first read without the caller having to arm it.
	done atomic.Bool
}

func (c *handshakeLimitedConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)

	// Finishing between the read starting and returning means these bytes
	// belong to the tunnel rather than to the negotiation, so they are not held
	// against the peer.
	if n > 0 && !c.done.Load() && c.read.Add(int64(n)) > c.limit {
		return n, ErrHandshakeTooLarge
	}

	return n, err
}

// Unwrap lets ArmReset and anything else that needs the socket underneath find
// it - see the unwrapper interface in this package.
func (c *handshakeLimitedConn) Unwrap() net.Conn { return c.Conn }
