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
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// useTempKnockCert points the TLS sign-in certificate at a fresh file for one
// test, and forgets the one in memory before and after.
func useTempKnockCert(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secure_tls.pem")
	old := knockCertFile
	knockCertFile = path
	resetKnockTLS()
	t.Cleanup(func() {
		knockCertFile = old
		resetKnockTLS()
	})
	return path
}

func resetKnockTLS() {
	knockTLSMu.Lock()
	defer knockTLSMu.Unlock()
	knockTLSCfg = nil
	knockTLSNotAfter = time.Time{}
}

type tlsReply struct {
	status int
	header http.Header
	body   string
	cert   []byte
	err    error
}

// tlsKnock speaks TLS on client the way a browser would - not checking the
// certificate, as a visitor who clicked through the warning - sends raw, and
// reads the answer.
func tlsKnock(client net.Conn, raw string) <-chan tlsReply {
	ch := make(chan tlsReply, 1)
	go func() {
		// The test plays a visitor who accepted the certificate warning.
		cfg := &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2", "http/1.1"}} // #nosec G402
		tc := tls.Client(client, cfg)
		if err := tc.Handshake(); err != nil {
			ch <- tlsReply{err: err}
			return
		}
		if _, err := tc.Write([]byte(raw)); err != nil {
			ch <- tlsReply{err: err}
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(tc), nil)
		if err != nil {
			ch <- tlsReply{err: err}
			return
		}
		body, err := io.ReadAll(resp.Body)
		ch <- tlsReply{
			status: resp.StatusCode, header: resp.Header, body: string(body),
			cert: tc.ConnectionState().PeerCertificates[0].Raw, err: err,
		}
		// Read on, as a browser does, so frps' close_notify is taken: a pipe,
		// unlike a socket, holds a write until somebody reads it.
		_, _ = io.Copy(io.Discard, tc)
	}()
	return ch
}

// The reported case: https:// to a tcp proxy whose backend terminates TLS
// itself - frpc's https2http plugin. frps cannot open that TLS, so it used to
// reset the visitor; now it signs them in over TLS of its own.
func TestATLSVisitorCanSignInOnARawPort(t *testing.T) {
	useTempKnockCert(t)
	g, _ := newTestGate(t, methods("basic"), "tcp")

	client, server := pipeFromVisitor(t)
	res := tlsKnock(client, "GET /api/tags HTTP/1.1\r\nHost: 203.0.113.5:7001\r\nAccept: text/html\r\n\r\n")
	_, v := g.AdmitConn(server)
	require.Equal(t, Answered, v, "answered by frps, not reset")
	r := <-res
	require.NoError(t, r.err)
	require.Equal(t, http.StatusUnauthorized, r.status)
	require.Equal(t, basicChallenge, r.header.Get("WWW-Authenticate"), "the browser asks for the title and key")

	client, server = pipeFromVisitor(t)
	auth := "Basic " + basicToken(testTitle, testKey)
	res = tlsKnock(client, "GET /api/tags HTTP/1.1\r\nHost: 203.0.113.5:7001\r\nAuthorization: "+auth+"\r\n\r\n")
	_, v = g.AdmitConn(server)
	require.Equal(t, Answered, v)
	r = <-res
	require.NoError(t, r.err)
	require.Equal(t, http.StatusTemporaryRedirect, r.status, "sent back to the same request, which now goes through")
	require.Equal(t, "/api/tags", r.header.Get("Location"))
	require.Equal(t, admitted, g.standingOf(visitor))
}

// The sign-in form over TLS: posting it unlocks, and the visitor is sent on to
// the page with a GET, the form having been the sign-in.
func TestTheSignInFormWorksOverTLS(t *testing.T) {
	useTempKnockCert(t)
	g, _ := newTestGate(t, methods("form"), "tcp")

	client, server := pipeFromVisitor(t)
	res := tlsKnock(client, "GET / HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n")
	_, _ = g.AdmitConn(server)
	r := <-res
	require.NoError(t, r.err)
	require.Contains(t, r.body, `name="frp_title"`)

	body := "frp_title=" + testTitle + "&frp_key=" + testKey
	client, server = pipeFromVisitor(t)
	res = tlsKnock(client, "POST /?x=1 HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n"+
		"Content-Length: "+strconv.Itoa(len(body))+"\r\n\r\n"+body)
	_, _ = g.AdmitConn(server)
	r = <-res
	require.NoError(t, r.err)
	require.Equal(t, http.StatusSeeOther, r.status)
	require.Equal(t, "/?x=1", r.header.Get("Location"))
	require.Equal(t, admitted, g.standingOf(visitor))
}

// Only raw ports. On an https proxy the TLS belongs to a domain with a
// certificate of its own and the unlock link lives on frps' http port; mc and
// udp never see TLS at all.
func TestTLSIsOnlyAnsweredOnRawPorts(t *testing.T) {
	useTempKnockCert(t)
	g, _ := newTestGate(t, methods("basic"), "https")
	client, server := pipeFromVisitor(t)
	go func() {
		_ = tls.Client(client, &tls.Config{InsecureSkipVerify: true}).Handshake() // #nosec G402 - nothing is verified here
	}()
	_, v := g.AdmitConn(server)
	require.Equal(t, Refuse, v)
}

// A browser that accepted the certificate once keeps accepting it: it is kept
// in a file and used again after a restart.
func TestTheSignInCertificateIsKeptAcrossRestarts(t *testing.T) {
	path := useTempKnockCert(t)

	first, err := knockTLSConfig()
	require.NoError(t, err)
	_, err = os.Stat(path)
	require.NoError(t, err, "written down")

	resetKnockTLS() // what a restart forgets
	second, err := knockTLSConfig()
	require.NoError(t, err)
	require.True(t, bytes.Equal(first.Certificates[0].Certificate[0], second.Certificates[0].Certificate[0]),
		"the same certificate after a restart")

	info, err := os.Stat(path)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "it holds a private key")
}

// One close to running out is replaced rather than served until browsers
// refuse it - whether it was read from the file or has aged in memory.
func TestAnAgingSignInCertificateIsReplaced(t *testing.T) {
	path := useTempKnockCert(t)
	aging, pemData, err := newKnockCert(time.Now().Add(knockCertRenewBefore / 2))
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(path, pemData, 0o600))

	cfg, err := knockTLSConfig()
	require.NoError(t, err)
	require.False(t, bytes.Equal(aging.Certificate[0], cfg.Certificates[0].Certificate[0]), "the aging one is not served")
	kept, err := os.ReadFile(path)
	require.NoError(t, err)
	require.False(t, bytes.Equal(pemData, kept), "and the file holds its replacement")

	// Aging in memory, as a long-running frps does: asked again, it is remade.
	knockTLSMu.Lock()
	knockTLSNotAfter = time.Now().Add(knockCertRenewBefore / 2)
	knockTLSMu.Unlock()
	require.NoError(t, os.Remove(path))
	again, err := knockTLSConfig()
	require.NoError(t, err)
	require.False(t, bytes.Equal(cfg.Certificates[0].Certificate[0], again.Certificates[0].Certificate[0]))
}

// A binary first byte is not waited on: a game that sends two bytes and waits
// for an answer is refused at once, not after the read deadline.
func TestOnlyATLSRecordIsWaitedOn(t *testing.T) {
	g, _ := newTestGate(t, methods("basic"), "tcp")
	client, server := pipeFromVisitor(t)
	go func() { _, _ = client.Write([]byte{0x01, 0x02}) }()

	start := time.Now()
	_, v := g.AdmitConn(server)
	require.Equal(t, Refuse, v)
	require.Less(t, time.Since(start), time.Second)
}
