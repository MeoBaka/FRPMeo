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
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// addrConn gives one end of a net.Pipe the source address of a real visitor.
type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c addrConn) RemoteAddr() net.Addr {
	return c.remote
}

// pipeFromVisitor is a connection whose far end is the test visitor.
func pipeFromVisitor(t *testing.T) (client, server net.Conn) {
	t.Helper()
	c, s := net.Pipe()
	t.Cleanup(func() {
		_ = c.Close()
		_ = s.Close()
	})
	return c, addrConn{Conn: s, remote: &net.TCPAddr{IP: visitor.AsSlice(), Port: 40000}}
}

type knockResult struct {
	status int
	body   string
	err    error
}

// knock sends raw on client and reads the HTTP answer to it.
func knock(client net.Conn, raw string) <-chan knockResult {
	ch := make(chan knockResult, 1)
	go func() {
		if _, err := client.Write([]byte(raw)); err != nil {
			ch <- knockResult{err: err}
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			ch <- knockResult{err: err}
			return
		}
		body, err := io.ReadAll(resp.Body)
		ch <- knockResult{status: resp.StatusCode, body: string(body), err: err}
	}()
	return ch
}

func TestALinkUnlocksTheAddress(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "tcp")
	client, server := pipeFromVisitor(t)

	res := knock(client, "GET /?dangnhap=secret123 HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, v := g.AdmitConn(server)
	require.Equal(t, Answered, v, "an unlock request is answered by frps, not forwarded")

	r := <-res
	require.NoError(t, r.err)
	require.Equal(t, http.StatusOK, r.status)
	require.Contains(t, r.body, "192.0.2.1")
	require.Equal(t, admitted, g.standingOf(visitor))
}

func TestAHeaderKeyInAnyRequestUnlocks(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "tcp")
	client, server := pipeFromVisitor(t)

	res := knock(client, "POST / HTTP/1.1\r\nHost: example.com\r\nDangnhap: secret123\r\nContent-Length: 0\r\n\r\n")
	_, v := g.AdmitConn(server)
	require.Equal(t, Answered, v)
	require.Equal(t, http.StatusOK, (<-res).status)
	require.Equal(t, admitted, g.standingOf(visitor))
}

func TestAWrongLinkIsRefusedAndCounted(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{AntiSpam: v1.SecureAntiSpamConfig{MaxFailures: 1}}, "tcp")
	client, server := pipeFromVisitor(t)

	res := knock(client, "GET /?dangnhap=guess HTTP/1.1\r\nHost: example.com\r\n\r\n")
	_, v := g.AdmitConn(server)
	require.Equal(t, Answered, v)
	require.Equal(t, http.StatusForbidden, (<-res).status)
	require.Equal(t, refused, g.standingOf(visitor), "one wrong key is the limit here")
}

func TestARequestWithoutAKeyGetsTheLoginPage(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "tcp")
	client, server := pipeFromVisitor(t)

	res := knock(client, "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n")
	_, v := g.AdmitConn(server)
	require.Equal(t, Answered, v)

	r := <-res
	require.Equal(t, http.StatusUnauthorized, r.status)
	require.Contains(t, r.body, `name="dangnhap"`)
	require.Equal(t, unknown, g.standingOf(visitor))
}

func TestAKeyLinePassesTheRestThrough(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "tcp")
	client, server := pipeFromVisitor(t)

	go func() { _, _ = client.Write([]byte("dangnhap: secret123\r\nhello")) }()
	conn, v := g.AdmitConn(server)
	require.Equal(t, Pass, v)

	buf := make([]byte, 5)
	_, err := io.ReadFull(conn, buf)
	require.NoError(t, err)
	require.Equal(t, "hello", string(buf), "the backend gets what followed the line, and not the line")
	require.Equal(t, unknown, g.standingOf(visitor), "a line admits its connection, not the address")
}

func TestAWrongKeyLineIsRefusedAndCounted(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{AntiSpam: v1.SecureAntiSpamConfig{MaxFailures: 1}}, "tcp")
	client, server := pipeFromVisitor(t)

	go func() { _, _ = client.Write([]byte("dangnhap: guess\n")) }()
	_, v := g.AdmitConn(server)
	require.Equal(t, Refuse, v)
	require.Equal(t, refused, g.standingOf(visitor))
}

func TestABinaryHandshakeIsRefusedAtOnce(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "tcp")
	client, server := pipeFromVisitor(t)

	go func() { _, _ = client.Write([]byte{0x10, 0x00, 0xf5, 0x05, 0x09}) }()
	start := time.Now()
	_, v := g.AdmitConn(server)

	require.Equal(t, Refuse, v)
	require.Less(t, time.Since(start), knockTimeout/2, "no waiting for a line that cannot be one")
}

func TestLinesAreIgnoredWhenTheMethodIsOff(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{Methods: []string{v1.SecureMethodLink}}, "tcp")
	client, server := pipeFromVisitor(t)

	go func() { _, _ = client.Write([]byte("dangnhap: secret123\nhello")) }()
	_, v := g.AdmitConn(server)
	require.Equal(t, Refuse, v)
}

func TestAnAdmittedSourceGoesStraightThrough(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "tcp")
	g.unlock(visitor)
	_, server := pipeFromVisitor(t)

	conn, v := g.AdmitConn(server)
	require.Equal(t, Pass, v)
	require.Equal(t, server, conn, "nothing is read from an admitted source - a server that speaks first still works")
}

func TestABannedSourceIsRefusedWithoutReading(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{AntiSpam: v1.SecureAntiSpamConfig{MaxFailures: 1}}, "tcp")
	g.noteFailure(visitor)
	_, server := pipeFromVisitor(t)

	_, v := g.AdmitConn(server)
	require.Equal(t, Refuse, v)
}

func TestAKeyDatagramUnlocksItsSource(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "udp")

	require.False(t, g.AdmitPacket("192.0.2.1:5000", []byte("game data")))
	require.False(t, g.AdmitPacket("192.0.2.1:5000", []byte("dangnhap: secret123")),
		"the key datagram itself is not forwarded")
	require.True(t, g.AdmitPacket("192.0.2.1:5001", []byte("game data")),
		"the address is unlocked, whatever the port")
}

func TestOrdinaryPacketsAreNotCountedAsAttempts(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{AntiSpam: v1.SecureAntiSpamConfig{MaxAttemptsPerMinute: 2}}, "udp")

	for range 50 {
		g.AdmitPacket("192.0.2.1:5000", []byte("game data"))
	}
	require.Equal(t, unknown, g.standingOf(visitor), "a game retrying before its player unlocked is not spam")
}

func TestTheKnockListenerUnlocksByLine(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "udp")
	client, server := pipeFromVisitor(t)

	done := make(chan string, 1)
	go func() {
		_, _ = client.Write([]byte("dangnhap: secret123\n"))
		line, _ := bufio.NewReader(client).ReadString('\n')
		done <- line
	}()
	g.answerKnockConn(server)

	require.Contains(t, <-done, "unlocked")
	require.Equal(t, admitted, g.standingOf(visitor))
}
