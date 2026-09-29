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

package secure

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	netpkg "github.com/fatedier/frp/pkg/util/net"
)

const (
	// knockTimeout bounds how long a source that is not admitted gets to show
	// the key. Browsers and custom clients send at once; waiting longer would
	// only hold a socket open for a scanner.
	knockTimeout = 5 * time.Second

	// knockBufferSize bounds the first read, which is where a key line has to
	// be.
	knockBufferSize = 4096

	// maxKnockRequest bounds an unlock request, header and body together.
	maxKnockRequest = 16 << 10

	// maxKnockBody bounds the part of a body searched for the key.
	maxKnockBody = 4 << 10

	// maxLine bounds a key line - a title, a colon and a key, with room to
	// spare - and so also a key datagram.
	maxLine = 512
)

// Verdict is what a gate made of a connection.
type Verdict int

const (
	// Pass forwards the connection to the backend.
	Pass Verdict = iota

	// Refuse drops it. Callers close with RST.
	Refuse

	// Answered means frps answered the connection itself - it was an unlock
	// request - and it should be closed normally, so the answer arrives.
	Answered
)

var httpMethods = [][]byte{
	[]byte("GET "), []byte("POST "), []byte("PUT "), []byte("HEAD "),
	[]byte("PATCH "), []byte("DELETE "), []byte("OPTIONS "),
}

// AdmitConn decides a user connection of a tcp-family proxy. A source that is
// not admitted yet has to show the key on this very connection, so it may be
// read from: the conn returned replays whatever belongs to the backend.
func (g *Gate) AdmitConn(c net.Conn) (net.Conn, Verdict) {
	ip, ok := addrOf(c.RemoteAddr().String())
	if !ok {
		return c, Refuse
	}
	switch g.standingOf(ip) {
	case admitted:
		return c, Pass
	case refused:
		return c, Refuse
	}
	if !g.noteAttempt(ip) {
		return c, Refuse
	}

	_ = c.SetReadDeadline(time.Now().Add(knockTimeout))
	br := bufio.NewReaderSize(c, knockBufferSize)
	if _, err := br.Peek(1); err != nil {
		return c, Refuse
	}
	if g.TakesRequests() && looksLikeHTTP(br) {
		g.answerKnock(c, br, ip)
		return c, Answered
	}
	// Only wait for a whole line if what arrived could be one: a game's binary
	// handshake is refused at once rather than after the timeout.
	if g.line && g.mayBeLine(buffered(br)) {
		switch g.readLine(br) {
		case keyGood:
			_ = c.SetReadDeadline(time.Time{})
			return &replayConn{Conn: c, r: br}, Pass
		case keyWrong:
			g.noteFailure(ip)
		}
	}
	return c, Refuse
}

// ServeKnocks answers unlock requests on l until l is closed. A udp proxy
// cannot receive a link, so frps listens for one over tcp on the same port;
// nothing that arrives there is ever forwarded.
func (g *Gate) ServeKnocks(l net.Listener) {
	for {
		c, err := l.Accept()
		if err != nil {
			if ne, ok := err.(interface{ Temporary() bool }); ok && ne.Temporary() {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return
		}
		go g.answerKnockConn(c)
	}
}

func (g *Gate) answerKnockConn(c net.Conn) {
	defer c.Close()

	ip, ok := addrOf(c.RemoteAddr().String())
	if !ok || g.standingOf(ip) == refused || !g.noteAttempt(ip) {
		netpkg.ArmReset(c)
		return
	}
	_ = c.SetReadDeadline(time.Now().Add(knockTimeout))
	br := bufio.NewReaderSize(c, knockBufferSize)
	if _, err := br.Peek(1); err != nil {
		return
	}
	switch {
	case looksLikeHTTP(br):
		g.answerKnock(c, br, ip)
	case g.line && g.mayBeLine(buffered(br)):
		// With no stream behind it to pass on, a key line here unlocks the
		// address the way a link does.
		_ = c.SetWriteDeadline(time.Now().Add(knockTimeout))
		switch g.readLine(br) {
		case keyGood:
			g.unlock(ip)
			_, _ = fmt.Fprintf(c, "unlocked %s for %s\n", ip, humanDuration(g.unlockTTL))
		case keyWrong:
			g.noteFailure(ip)
			_, _ = io.WriteString(c, "wrong key\n")
		}
	}
}

// AdmitPacket decides one datagram of a udp-family proxy. A datagram carrying
// the key line unlocks its source and goes no further.
//
// Ordinary packets from a source that is not unlocked are dropped without being
// counted as attempts: a game retries many times a second, and a player who
// forgot to unlock first should not find the link banned when they do.
func (g *Gate) AdmitPacket(remoteAddr string, packet []byte) bool {
	ip, ok := addrOf(remoteAddr)
	if !ok {
		return false
	}
	switch g.standingOf(ip) {
	case admitted:
		return true
	case refused:
		return false
	}
	if g.line && len(packet) <= maxLine && g.mayBeLine(packet) {
		switch g.judgeLine(packet) {
		case keyGood:
			g.unlock(ip)
		case keyWrong:
			g.noteFailure(ip)
		}
	}
	return false
}

// answerKnock reads one HTTP request from a source that is not admitted,
// judges the key in it and answers. It never reaches the backend.
func (g *Gate) answerKnock(c net.Conn, br *bufio.Reader, ip netip.Addr) {
	_ = c.SetDeadline(time.Now().Add(knockTimeout))
	req, err := http.ReadRequest(bufio.NewReader(io.LimitReader(br, maxKnockRequest)))
	if err != nil {
		return
	}
	req.RemoteAddr = c.RemoteAddr().String()
	_ = g.knock(req, ip).write(c, req)
}

// knock judges an unlock request: one made to frps rather than to the
// backend. The right key unlocks the source address.
func (g *Gate) knock(req *http.Request, ip netip.Addr) answer {
	key, found := g.keyFromRequest(req)
	if !found {
		return g.loginPage(req)
	}
	if !g.keyMatches(key) {
		g.noteFailure(ip)
		return wrongKeyPage(req)
	}
	g.unlock(ip)
	return g.unlockedPage(req, ip)
}

// keyFromRequest finds a key where the enabled methods allow it: a header or a
// body field named after the title (http), or a query parameter (link).
func (g *Gate) keyFromRequest(req *http.Request) (string, bool) {
	if g.http {
		if v := req.Header.Get(g.title); v != "" {
			return v, true
		}
	}
	if g.link {
		if v, ok := g.queryKey(req); ok {
			return v, true
		}
	}
	if g.http {
		return g.bodyKey(req)
	}
	return "", false
}

func (g *Gate) queryKey(req *http.Request) (string, bool) {
	for name, values := range req.URL.Query() {
		if strings.EqualFold(name, g.title) && len(values) > 0 {
			return values[0], true
		}
	}
	return "", false
}

// bodyKey looks for a field named after the title in a JSON or form body.
func (g *Gate) bodyKey(req *http.Request) (string, bool) {
	if req.Body == nil {
		return "", false
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxKnockBody))
	if err != nil || len(body) == 0 {
		return "", false
	}
	if strings.HasPrefix(req.Header.Get("Content-Type"), "application/json") {
		var fields map[string]any
		if json.Unmarshal(body, &fields) != nil {
			return "", false
		}
		for name, v := range fields {
			if s, ok := v.(string); ok && strings.EqualFold(name, g.title) {
				return s, true
			}
		}
		return "", false
	}
	// A form, or a body sent with no type at all.
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return "", false
	}
	for name, v := range values {
		if strings.EqualFold(name, g.title) && len(v) > 0 {
			return v[0], true
		}
	}
	return "", false
}

type keyResult int

const (
	// keyAbsent: nothing shaped like "<title>: ...".
	keyAbsent keyResult = iota
	keyWrong
	keyGood
)

// mayBeLine reports whether what has arrived so far could start "<title>:".
func (g *Gate) mayBeLine(head []byte) bool {
	n := min(len(head), len(g.title))
	return n > 0 && bytes.EqualFold(head[:n], []byte(g.title[:n]))
}

func (g *Gate) readLine(br *bufio.Reader) keyResult {
	line, err := br.ReadSlice('\n')
	if err != nil || len(line) > maxLine {
		return keyAbsent
	}
	return g.judgeLine(line)
}

// judgeLine judges "<title>: <key>", with or without its line ending.
func (g *Gate) judgeLine(line []byte) keyResult {
	name, value, ok := strings.Cut(strings.TrimRight(string(line), "\r\n"), ":")
	if !ok || !strings.EqualFold(strings.TrimSpace(name), g.title) {
		return keyAbsent
	}
	if g.keyMatches(strings.TrimSpace(value)) {
		return keyGood
	}
	return keyWrong
}

// looksLikeHTTP reports whether the bytes that have arrived start an HTTP
// request.
func looksLikeHTTP(br *bufio.Reader) bool {
	head, _ := br.Peek(min(br.Buffered(), 8))
	for _, m := range httpMethods {
		if bytes.HasPrefix(head, m) {
			return true
		}
	}
	return false
}

func buffered(br *bufio.Reader) []byte {
	b, _ := br.Peek(br.Buffered())
	return b
}

// replayConn hands the backend what was read while looking for the key line.
type replayConn struct {
	net.Conn
	r *bufio.Reader
}

func (c *replayConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// Unwrap lets netpkg.ArmReset reach the socket underneath.
func (c *replayConn) Unwrap() net.Conn {
	return c.Conn
}
