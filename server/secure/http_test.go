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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// httptest.NewRequest comes from 192.0.2.1, which is the test visitor.

func TestAHeaderKeyPassesAndIsStripped(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "http")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Dangnhap", testKey)

	require.True(t, g.CheckHTTP(req).Allowed)
	require.Empty(t, req.Header.Get("Dangnhap"), "the backend must not see the key")
	require.Equal(t, unknown, g.standingOf(visitor), "a header proves one request, it unlocks nothing")
}

func TestAWrongHeaderKeyIsRefused(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "http")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Dangnhap", "guess")

	d := g.CheckHTTP(req)
	require.False(t, d.Allowed)
	require.Equal(t, http.StatusForbidden, d.StatusCode)
}

func TestAnAppWithTheRightHeaderIsNeverRateLimited(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{AntiSpam: v1.SecureAntiSpamConfig{MaxAttemptsPerMinute: 2}}, "http")

	for range 20 {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/api", nil)
		req.Header.Set("Dangnhap", testKey)
		require.True(t, g.CheckHTTP(req).Allowed)
	}
}

func TestALinkUnlocksSetsACookieAndDropsTheKeyFromTheURL(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "http")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/page?a=1&dangnhap="+testKey, nil)

	d := g.CheckHTTP(req)
	require.False(t, d.Allowed, "the link is answered with a redirect, not forwarded")
	require.Equal(t, http.StatusFound, d.StatusCode)
	require.Equal(t, "/page?a=1", d.Header.Get("Location"))
	require.Equal(t, admitted, g.standingOf(visitor))

	setCookie := d.Header.Get("Set-Cookie")
	require.True(t, strings.HasPrefix(setCookie, g.cookieName+"="))
	require.Contains(t, setCookie, "HttpOnly")

	// From another address, only the cookie can carry the browser in.
	next := httptest.NewRequest(http.MethodGet, "http://example.com/page?a=1", nil)
	next.RemoteAddr = "198.51.100.9:1234"
	next.Header.Set("Cookie", strings.SplitN(setCookie, ";", 2)[0]+"; other=1")

	require.True(t, g.CheckHTTP(next).Allowed)
	require.Equal(t, "other=1", next.Header.Get("Cookie"), "the unlock cookie is stripped, the site's own kept")
}

func TestAWrongLinkIsRefused(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "http")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/?dangnhap=guess", nil)

	d := g.CheckHTTP(req)
	require.Equal(t, http.StatusForbidden, d.StatusCode)
	require.Equal(t, unknown, g.standingOf(visitor))
}

func TestBrowsersWithoutAKeyGetTheLoginPage(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "http")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	d := g.CheckHTTP(req)
	require.Equal(t, http.StatusUnauthorized, d.StatusCode)
	require.Contains(t, string(d.Body), `name="dangnhap"`)
	require.Contains(t, string(d.Body), `method="post"`)
	require.Equal(t, "text/html; charset=utf-8", d.Header.Get("Content-Type"))
}

func TestTheLoginFormUsesTheQueryWhenOnlyLinksAreOn(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{Methods: []string{v1.SecureMethodLink}}, "http")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Accept", "text/html")

	require.Contains(t, string(g.CheckHTTP(req).Body), `method="get"`)
}

func TestTheLoginFormPostUnlocks(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "http")
	req := httptest.NewRequest(http.MethodPost, "http://example.com/app", strings.NewReader("dangnhap="+testKey))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	d := g.CheckHTTP(req)
	require.Equal(t, http.StatusSeeOther, d.StatusCode)
	require.Equal(t, "/app", d.Header.Get("Location"))
	require.Equal(t, admitted, g.standingOf(visitor))
}

func TestAnUnlockedAddressIsLetThroughWithTheKeyStripped(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "http")
	g.unlock(visitor)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)

	require.True(t, g.CheckHTTP(req).Allowed)
}

func TestTheRedirectNeverLeavesTheSite(t *testing.T) {
	g, _ := newTestGate(t, v1.SecureConfig{}, "http")
	u, err := url.Parse("http://example.com//evil.example/x?dangnhap=k&b=2")
	require.NoError(t, err)

	require.Equal(t, "/evil.example/x?b=2", g.withoutKey(u), `"//host" would be a link to another site`)
}

func TestTheKnockRegistryFindsWildcardDomains(t *testing.T) {
	r := NewKnockRegistry()
	g, _ := newTestGate(t, v1.SecureConfig{}, "https")
	other, _ := newTestGate(t, v1.SecureConfig{}, "https")

	r.Register("*.example.com", g)
	require.Same(t, g, r.lookup("a.example.com:80"))
	require.Same(t, g, r.lookup("A.B.Example.com"))
	require.Nil(t, r.lookup("example.org"))

	r.Unregister("*.example.com", other)
	require.Same(t, g, r.lookup("a.example.com"), "only the gate that registered a domain can remove it")

	r.Unregister("*.example.com", g)
	require.Nil(t, r.lookup("a.example.com"))
}

func TestTheKnockRegistryAnswersForItsDomainsOnly(t *testing.T) {
	r := NewKnockRegistry()
	g, _ := newTestGate(t, v1.SecureConfig{}, "https")
	r.Register("secure.example.com", g)

	rw := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://secure.example.com/?dangnhap="+testKey, nil)
	require.True(t, r.ServeNoRoute(rw, req))
	require.Equal(t, http.StatusOK, rw.Code)
	require.Equal(t, admitted, g.standingOf(visitor))

	require.False(t, r.ServeNoRoute(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://other.example.com/", nil)))
}
