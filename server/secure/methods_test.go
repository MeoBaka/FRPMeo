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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// Tests for the ways of presenting the key beyond the first version's link,
// http and line: the sign-in prompt (basic), bearer tokens, and header, form
// and json chosen one at a time.

func methods(m ...string) v1.SecureConfig {
	return v1.SecureConfig{Methods: m}
}

func browserGet(target string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	req.Header.Set("Accept", "text/html")
	return req
}

// --- the sign-in prompt, on an http proxy ---

// Going straight to the site asks for the title and the key the way a site
// asks for a username and a password: the browser's own prompt.
func TestBasicAsksForTheTitleAndKeyLikeAUsernameAndPassword(t *testing.T) {
	g, _ := newTestGate(t, methods("basic"), "http")

	d := g.CheckHTTP(browserGet("http://example.com/"))
	require.False(t, d.Allowed)
	require.Equal(t, http.StatusUnauthorized, d.StatusCode)
	require.Equal(t, basicChallenge, d.Header.Get("WWW-Authenticate"))
	require.Contains(t, string(d.Body), "username", "a visitor who cancels the prompt is told how to get it back")
	require.NotContains(t, string(d.Body), testTitle, "the title is the username here, so the page does not give it away")
}

func TestBasicCredentialsLetTheVisitorInAndNeverReachTheBackend(t *testing.T) {
	g, _ := newTestGate(t, methods("basic"), "http")
	req := browserGet("http://example.com/page")
	req.SetBasicAuth("DangNhap", testKey) // usernames compare like the title does elsewhere

	require.True(t, g.CheckHTTP(req).Allowed)
	require.Empty(t, req.Header.Get("Authorization"), "the backend must not see the key")
	require.Equal(t, admitted, g.standingOf(visitor), "a sign-in unlocks the address, like a link")
}

func TestAWrongPasswordIsCountedAndAskedForAgain(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{Methods: []string{"basic"}, AntiSpam: v1.SecureAntiSpamConfig{MaxFailures: 2}}, "http")

	for i := range 2 {
		req := browserGet("http://example.com/")
		req.SetBasicAuth(testTitle, "guess")
		d := g.CheckHTTP(req)
		require.Equal(t, http.StatusUnauthorized, d.StatusCode, "attempt %d is asked again, like any site", i+1)
		require.Equal(t, basicChallenge, d.Header.Get("WWW-Authenticate"))
	}
	require.Equal(t, refused, g.standingOf(visitor), "wrong passwords are wrong keys")
}

// Credentials for another username belong to somebody else - the backend's own
// sign-in, after the unlock ran out - and are neither a wrong key nor passed.
func TestBasicCredentialsForAnotherUserAreNotAWrongKey(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{Methods: []string{"basic"}, AntiSpam: v1.SecureAntiSpamConfig{MaxFailures: 1}}, "http")
	req := browserGet("http://example.com/")
	req.SetBasicAuth("admin", "router-password")

	d := g.CheckHTTP(req)
	require.Equal(t, http.StatusUnauthorized, d.StatusCode)
	require.Equal(t, basicChallenge, d.Header.Get("WWW-Authenticate"), "our own prompt comes back")
	require.Equal(t, unknown, g.standingOf(visitor), "not counted as a wrong key")
}

// Once in, the backend's own sign-in has to work: its credentials replace ours
// in the browser, and they are passed on untouched.
func TestTheBackendsOwnSignInPassesOnceUnlocked(t *testing.T) {
	g, _ := newTestGate(t, methods("basic"), "http")
	first := browserGet("http://example.com/")
	first.SetBasicAuth(testTitle, testKey)
	require.True(t, g.CheckHTTP(first).Allowed)

	next := browserGet("http://example.com/admin")
	next.SetBasicAuth("admin", "router-password")
	require.True(t, g.CheckHTTP(next).Allowed)
	user, pass, ok := next.BasicAuth()
	require.True(t, ok, "someone else's credentials are left for the backend")
	require.Equal(t, "admin", user)
	require.Equal(t, "router-password", pass)
}

// --- bearer tokens ---

func TestABearerTokenPassesAndIsStripped(t *testing.T) {
	g, _ := newTestGate(t, methods("bearer"), "http")
	req := httptest.NewRequest(http.MethodPost, "http://example.com/v1/chat", strings.NewReader(`{"model":"x"}`))
	req.Header.Set("Authorization", "Bearer "+testKey)

	require.True(t, g.CheckHTTP(req).Allowed)
	require.Empty(t, req.Header.Get("Authorization"), "the backend must not see the key")
	require.Equal(t, unknown, g.standingOf(visitor), "a token proves one request, like a header")

	wrong := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	wrong.Header.Set("Authorization", "Bearer guess")
	d := g.CheckHTTP(wrong)
	require.Equal(t, http.StatusForbidden, d.StatusCode)
	require.Empty(t, d.Header.Get("WWW-Authenticate"), "only basic asks again")
}

func TestAnAPIClientWithTheRightTokenIsNeverRateLimited(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{Methods: []string{"bearer"}, AntiSpam: v1.SecureAntiSpamConfig{MaxAttemptsPerMinute: 2}}, "http")
	for range 20 {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/api/tags", nil)
		req.Header.Set("Authorization", "Bearer "+testKey)
		require.True(t, g.CheckHTTP(req).Allowed)
	}
}

// basic and bearer are only on when chosen. The defaults are what the first
// version took, and a config written for it must not start prompting.
func TestBasicAndBearerAreOptIn(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "http")

	req := browserGet("http://example.com/")
	req.Header.Set("Authorization", "Bearer "+testKey)
	d := g.CheckHTTP(req)
	require.False(t, d.Allowed, "a bearer token is not taken unless bearer is on")
	require.Empty(t, d.Header.Get("WWW-Authenticate"), "no prompt unless basic is on")

	req = browserGet("http://example.com/")
	req.SetBasicAuth(testTitle, testKey)
	require.False(t, g.CheckHTTP(req).Allowed, "basic credentials are not taken unless basic is on")
}

// --- header, form and json one at a time ---

func TestEachHTTPWayCanBeChosenOnItsOwn(t *testing.T) {
	type way struct {
		name string
		req  func() *http.Request
	}
	header := way{"header", func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Header.Set("Dangnhap", testKey)
		return req
	}}
	form := way{"form", func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader(url.Values{testTitle: {testKey}}.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return req
	}}
	json := way{"json", func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader(`{"dangnhap":"`+testKey+`"}`))
		req.Header.Set("Content-Type", "application/json")
		return req
	}}
	// A way that is on gets the visitor in or unlocks them; one that is off
	// leaves them where they were.
	works := func(g *Gate, w way) bool {
		d := g.CheckHTTP(w.req())
		return d.Allowed || g.standingOf(visitor) == admitted
	}

	for _, on := range []way{header, form, json} {
		t.Run(on.name, func(t *testing.T) {
			for _, w := range []way{header, form, json} {
				g, _ := newTestGate(t, methods(on.name), "http")
				require.Equal(t, w.name == on.name, works(g, w), "%s with only %s on", w.name, on.name)
			}
		})
	}
}

// The page's own form can only send what is on: a form field, or a link.
func TestTheLoginPageFollowsTheWaysThatAreOn(t *testing.T) {
	cases := []struct {
		methods    []string
		wantForm   string
		wantPrompt bool
	}{
		{methods: []string{"form"}, wantForm: `method="post"`},
		{methods: []string{"link"}, wantForm: `method="get"`},
		{methods: []string{"basic", "form"}, wantForm: `method="post"`, wantPrompt: true},
		{methods: []string{"json"}},
		{methods: []string{"bearer", "header"}},
	}
	for _, tc := range cases {
		t.Run(strings.Join(tc.methods, "+"), func(t *testing.T) {
			g, _ := newTestGate(t, methods(tc.methods...), "http")
			d := g.CheckHTTP(browserGet("http://example.com/"))
			require.Equal(t, http.StatusUnauthorized, d.StatusCode)
			require.Equal(t, tc.wantPrompt, d.Header.Get("WWW-Authenticate") != "")
			if tc.wantForm != "" {
				require.Contains(t, string(d.Body), tc.wantForm)
			} else {
				require.NotContains(t, string(d.Body), "<form", "no form can send this key")
			}
		})
	}
}

func TestClientsThatAreNotBrowsersAreToldHow(t *testing.T) {
	g, _ := newTestGate(t, methods("basic", "bearer"), "http")
	d := g.CheckHTTP(httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	body := string(d.Body)
	require.Contains(t, body, "basic auth")
	require.Contains(t, body, "Bearer")
	require.NotContains(t, body, testTitle, "with no way that needs the title as a name, it stays unsaid")

	g, _ = newTestGate(t, methods("header"), "http")
	d = g.CheckHTTP(httptest.NewRequest(http.MethodGet, "http://example.com/", nil))
	require.Contains(t, string(d.Body), "<title>: <key> header")
	require.NotContains(t, string(d.Body), testTitle, "the ways are named, not the titles: a title is half a login")
}

// --- on a raw port ---

type knockReply struct {
	status int
	header http.Header
	body   string
	err    error
}

// knockFull is knock, keeping the response headers.
func knockFull(client io.ReadWriter, raw string) <-chan knockReply {
	ch := make(chan knockReply, 1)
	go func() {
		if _, err := client.Write([]byte(raw)); err != nil {
			ch <- knockReply{err: err}
			return
		}
		resp, err := http.ReadResponse(bufio.NewReader(client), nil)
		if err != nil {
			ch <- knockReply{err: err}
			return
		}
		body, err := io.ReadAll(resp.Body)
		ch <- knockReply{status: resp.StatusCode, header: resp.Header, body: string(body), err: err}
	}()
	return ch
}

// On a tcp proxy the prompt unlocks the address, and the page that confirms it
// links back to the website the visitor came for, if that is what is there.
func TestBasicUnlocksARawPort(t *testing.T) {
	g, _ := newTestGate(t, methods("basic"), "tcp")

	client, server := pipeFromVisitor(t)
	res := knockFull(client, "GET /app HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\n\r\n")
	_, v := g.AdmitConn(server)
	require.Equal(t, Answered, v)
	r := <-res
	require.NoError(t, r.err)
	require.Equal(t, http.StatusUnauthorized, r.status)
	require.Equal(t, basicChallenge, r.header.Get("WWW-Authenticate"))

	client, server = pipeFromVisitor(t)
	auth := "Basic " + basicToken(testTitle, testKey)
	res = knockFull(client, "GET /app HTTP/1.1\r\nHost: example.com\r\nAccept: text/html\r\nAuthorization: "+auth+"\r\n\r\n")
	_, v = g.AdmitConn(server)
	require.Equal(t, Answered, v)
	r = <-res
	require.NoError(t, r.err)
	require.Equal(t, http.StatusOK, r.status)
	require.Contains(t, r.body, `href="http://example.com/app"`, "a way back to the page")
	require.Contains(t, r.body, `href="https://example.com/app"`, "over https too, for a backend behind TLS")
	require.Equal(t, admitted, g.standingOf(visitor))
}

// API clients send the token with every request and want the backend's answer,
// so on a raw port the request that proves the key goes through - without it.
func TestABearerRequestGoesThroughToTheBackend(t *testing.T) {
	g, _ := newTestGate(t, methods("bearer"), "tcp")
	client, server := pipeFromVisitor(t)

	raw := "POST /api/chat HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer " + testKey + "\r\n" +
		"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"
	go func() { _, _ = client.Write([]byte(raw)) }()

	conn, v := g.AdmitConn(server)
	require.Equal(t, Pass, v)

	req, err := http.ReadRequest(bufio.NewReader(conn))
	require.NoError(t, err)
	require.Equal(t, "/api/chat", req.URL.Path)
	require.Empty(t, req.Header.Get("Authorization"), "the backend must not see the key")
	require.Equal(t, "application/json", req.Header.Get("Content-Type"), "everything else arrives as sent")
	body, err := io.ReadAll(io.LimitReader(req.Body, 2))
	require.NoError(t, err)
	require.Equal(t, "{}", string(body))
	require.Equal(t, admitted, g.standingOf(visitor), "the client's next connections are not counted as attempts")
}

func TestAWrongBearerOnARawPortIsAnsweredAndCounted(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{Methods: []string{"bearer"}, AntiSpam: v1.SecureAntiSpamConfig{MaxFailures: 1}}, "tcp")
	client, server := pipeFromVisitor(t)

	res := knockFull(client, "GET / HTTP/1.1\r\nHost: example.com\r\nAuthorization: Bearer guess\r\n\r\n")
	_, v := g.AdmitConn(server)
	require.Equal(t, Answered, v, "a wrong token never reaches the backend")
	require.Equal(t, http.StatusForbidden, (<-res).status)
	require.Equal(t, refused, g.standingOf(visitor), "counted, once")
}

// A header block too large to look at in passing is still judged - by the
// knock, which unlocks rather than passes.
func TestALargeBearerRequestIsStillJudged(t *testing.T) {
	g, _ := newTestGate(t, methods("bearer"), "tcp")
	client, server := pipeFromVisitor(t)

	raw := "GET / HTTP/1.1\r\nHost: example.com\r\nX-Padding: " + strings.Repeat("a", knockBufferSize) + "\r\n" +
		"Authorization: Bearer " + testKey + "\r\n\r\n"
	res := knockFull(client, raw)
	_, v := g.AdmitConn(server)
	require.Equal(t, Answered, v)
	require.Equal(t, http.StatusOK, (<-res).status)
	require.Equal(t, admitted, g.standingOf(visitor))
}

func TestWithoutKeyHeadersTakesOutOnlyTheKey(t *testing.T) {
	g, _ := newTestGate(t, methods("bearer", "header"), "tcp")
	raw := "GET / HTTP/1.1\r\n" +
		"Host: example.com\r\n" +
		"Dangnhap: " + testKey + "\r\n" +
		"Authorization: Bearer " + testKey + "\r\n" +
		"X-Folded: one\r\n two\r\n" +
		"Authorization: Bearer someone-elses\r\n\r\n"

	got := string(g.withoutKeyHeaders([]byte(raw)))
	require.Equal(t, "GET / HTTP/1.1\r\n"+
		"Host: example.com\r\n"+
		"X-Folded: one\r\n two\r\n"+
		"Authorization: Bearer someone-elses\r\n\r\n", got)
}

// The way back to the page only where the page is: a tcp port's backend. On
// mc, udp or https the request came in somewhere the website is not.
func TestTheUnlockedPageLinksBackOnRawPortsOnly(t *testing.T) {
	for typ, want := range map[string]bool{"tcp": true, "tcp+udp": true, "mc": false, "udp": false, "https": false} {
		g, _ := newTestGate(t, v1.SecureConfig{}, typ)
		require.Equal(t, want, g.rawPort, typ)
	}
}

func basicToken(user, pass string) string {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth(user, pass)
	return strings.TrimPrefix(req.Header.Get("Authorization"), "Basic ")
}
