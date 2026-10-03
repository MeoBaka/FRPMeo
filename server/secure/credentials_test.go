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

// More than one title/key pair: each a login of its own.

const (
	annaTitle = "anna"
	annaKey   = "anna-key-1"
)

func twoLogins(m ...string) v1.SecureConfig {
	return v1.SecureConfig{
		Methods:     m,
		Credentials: []v1.SecureCredential{{Title: annaTitle, Key: annaKey}},
	}
}

func TestEveryLoginOpensTheProxy(t *testing.T) {
	g, _ := newTestGate(t, twoLogins("header"), "http")

	for _, c := range []struct{ title, key string }{{testTitle, testKey}, {annaTitle, annaKey}} {
		req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
		req.Header.Set(c.title, c.key)
		require.True(t, g.CheckHTTP(req).Allowed, c.title)
		require.Empty(t, req.Header.Get(c.title), "the backend must not see the key")
	}
}

// A key opens the proxy under its own title only: logins are pairs, not a pool
// of titles and a pool of keys.
func TestAKeyOnlyWorksUnderItsOwnTitle(t *testing.T) {
	g, _ := newTestGate(t, twoLogins("header"), "http")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set(annaTitle, testKey)

	d := g.CheckHTTP(req)
	require.False(t, d.Allowed)
	require.Equal(t, http.StatusForbidden, d.StatusCode, "the wrong key for that login")
}

func TestEveryLoginWorksAtTheSignInPrompt(t *testing.T) {
	g, _ := newTestGate(t, twoLogins("basic"), "http")
	req := browserGet("http://example.com/")
	req.SetBasicAuth("Anna", annaKey)
	require.True(t, g.CheckHTTP(req).Allowed)

	// A fresh gate: the sign-in above unlocked this address.
	g, _ = newTestGate(t, twoLogins("basic"), "http")
	wrong := browserGet("http://example.com/")
	wrong.SetBasicAuth(annaTitle, testKey)
	require.Equal(t, http.StatusUnauthorized, g.CheckHTTP(wrong).StatusCode)
}

// A bearer token names no title, so any login's key is a token.
func TestABearerTokenMayBeAnyLoginsKey(t *testing.T) {
	g, _ := newTestGate(t, twoLogins("bearer"), "http")
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set("Authorization", "Bearer "+annaKey)
	require.True(t, g.CheckHTTP(req).Allowed)
}

// The sign-in page asks for both halves of a login, the way a site asks for a
// username and a password.
func TestTheSignInFormTakesATitleAndAKey(t *testing.T) {
	post := func(g *Gate, title, key string) int {
		form := url.Values{v1.SecureFormTitleField: {title}, v1.SecureFormKeyField: {key}}
		req := httptest.NewRequest(http.MethodPost, "http://example.com/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return g.CheckHTTP(req).StatusCode
	}

	g, _ := newTestGate(t, twoLogins("form"), "http")
	require.Equal(t, http.StatusSeeOther, post(g, "ANNA", annaKey), "unlocks and redirects")
	require.Equal(t, admitted, g.standingOf(visitor))

	strict := twoLogins("form")
	strict.AntiSpam.MaxFailures = 2
	g, _ = newTestGate(t, strict, "http")
	require.Equal(t, http.StatusForbidden, post(g, annaTitle, testKey), "somebody else's key")
	require.Equal(t, http.StatusForbidden, post(g, "nobody", annaKey), "a title that is no login")
	require.Equal(t, refused, g.standingOf(visitor), "both count as wrong keys")
}

// The link form of the sign-in, for a proxy with link on and form off: the
// pair travels in the query and is taken out of the URL the visitor is sent
// back to.
func TestTheSignInPairInALinkIsTakenOutOfTheURL(t *testing.T) {
	g, _ := newTestGate(t, twoLogins("link"), "http")
	q := url.Values{"page": {"2"}, v1.SecureFormTitleField: {annaTitle}, v1.SecureFormKeyField: {annaKey}}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/list?"+q.Encode(), nil)

	d := g.CheckHTTP(req)
	require.Equal(t, http.StatusFound, d.StatusCode)
	require.Equal(t, "/list?page=2", d.Header.Get("Location"))
	require.Equal(t, admitted, g.standingOf(visitor))
}

func TestEveryLoginWorksAsAKeyLine(t *testing.T) {
	g, _ := newTestGate(t, twoLogins("line"), "tcp")
	require.True(t, g.mayBeLine([]byte("an")), "a line may start with any of the titles")
	require.Equal(t, keyGood, g.judgeLine([]byte("Anna: "+annaKey+"\r\n")))
	require.Equal(t, keyWrong, g.judgeLine([]byte("anna: "+testKey+"\r\n")))
	require.Equal(t, keyAbsent, g.judgeLine([]byte("bob: "+annaKey+"\r\n")))
}

// Cookies belong to the keys they were issued under: changing any login's key
// logs every browser out, reordering the logins does not.
func TestCookiesBelongToAllTheKeys(t *testing.T) {
	g, now := newTestGate(t, twoLogins(), "http")
	cookie := g.cookieValue(now.Add(g.unlockTTL))

	reordered, _ := newTestGate(t, v1.SecureConfig{
		Title: annaTitle, Key: annaKey,
		Credentials: []v1.SecureCredential{{Title: testTitle, Key: testKey}},
	}, "http")
	reordered.now = g.now
	require.True(t, reordered.cookieValid(cookie))

	changed, _ := newTestGate(t, v1.SecureConfig{Credentials: []v1.SecureCredential{{Title: annaTitle, Key: "anna-key-2"}}}, "http")
	changed.now = g.now
	require.False(t, changed.cookieValid(cookie))
}

func TestEveryTitleHeaderIsKeptFromTheBackend(t *testing.T) {
	g, _ := newTestGate(t, twoLogins("header"), "http")
	g.unlock(visitor)
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	req.Header.Set(testTitle, testKey)
	req.Header.Set(annaTitle, annaKey)

	require.True(t, g.CheckHTTP(req).Allowed)
	require.Empty(t, req.Header.Get(testTitle))
	require.Empty(t, req.Header.Get(annaTitle))
}
