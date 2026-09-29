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
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/fatedier/frp/pkg/util/vhost"
)

// CheckHTTP decides one request to an http proxy. A request carries its own
// proof - the cookie an earlier unlock set, the key in a header, or an address
// that is unlocked or trusted. A link or the login form unlocks and redirects;
// anything else gets the login page. The key is stripped from a request before
// it is forwarded, so the backend never sees it.
func (g *Gate) CheckHTTP(req *http.Request) vhost.AllowDecision {
	ip, ok := addrOf(req.RemoteAddr)
	if !ok {
		return vhost.AllowDecision{StatusCode: http.StatusForbidden}
	}
	st := g.standingOf(ip)
	if st == refused {
		return vhost.AllowDecision{StatusCode: http.StatusForbidden}
	}
	// Honored even for an admitted source, so the key is never passed on to
	// the backend in a URL.
	if g.link {
		if key, found := g.queryKey(req); found {
			return g.unlockAndRedirect(req, ip, key, http.StatusFound)
		}
	}
	if st == admitted || g.hasValidCookie(req) {
		g.strip(req)
		return vhost.AllowDecisionOK
	}
	// A key in a header proves itself on every request - the way for apps and
	// scripts that keep no cookies - so the right one is never counted.
	if g.http {
		if v := req.Header.Get(g.title); v != "" {
			if g.keyMatches(v) {
				g.strip(req)
				return vhost.AllowDecisionOK
			}
			g.noteFailure(ip)
			return wrongKeyPage(req).decision()
		}
	}
	if !g.noteAttempt(ip) {
		return vhost.AllowDecision{StatusCode: http.StatusForbidden}
	}
	if g.http && req.Method == http.MethodPost {
		if key, found := g.bodyKey(req); found {
			return g.unlockAndRedirect(req, ip, key, http.StatusSeeOther)
		}
	}
	return g.loginPage(req).decision()
}

// ServeKnock answers an unlock request that reached frps' http port for a
// domain of a secure https proxy. TLS passes through frps untouched, so this
// is the only place such a proxy can take a key.
func (g *Gate) ServeKnock(rw http.ResponseWriter, req *http.Request) {
	ip, ok := addrOf(req.RemoteAddr)
	if !ok || g.standingOf(ip) == refused || !g.noteAttempt(ip) {
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)
		return
	}
	g.knock(req, ip).serve(rw)
}

// unlockAndRedirect judges a key from a link or the login form. The right one
// unlocks the source and sets a cookie - which keeps a browser in when its
// address changes - then sends it back to the page without the key in the URL.
func (g *Gate) unlockAndRedirect(req *http.Request, ip netip.Addr, key string, status int) vhost.AllowDecision {
	if !g.keyMatches(key) {
		g.noteFailure(ip)
		return wrongKeyPage(req).decision()
	}
	g.unlock(ip)
	cookie := &http.Cookie{
		Name:     g.cookieName,
		Value:    g.cookieValue(g.now().Add(g.unlockTTL)),
		Path:     "/",
		MaxAge:   int(g.unlockTTL / time.Second),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   req.TLS != nil,
	}
	h := make(http.Header)
	h.Add("Set-Cookie", cookie.String())
	h.Set("Location", g.withoutKey(req.URL))
	return answer{status: status, header: h}.decision()
}

func (g *Gate) hasValidCookie(req *http.Request) bool {
	c, err := req.Cookie(g.cookieName)
	return err == nil && g.cookieValid(c.Value)
}

// strip removes the key header and the unlock cookie from a request on its way
// to the backend.
func (g *Gate) strip(req *http.Request) {
	req.Header.Del(g.title)
	cookies := req.Cookies()
	found := false
	for _, c := range cookies {
		if c.Name == g.cookieName {
			found = true
			break
		}
	}
	if !found {
		return
	}
	req.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != g.cookieName {
			req.AddCookie(c)
		}
	}
}

// withoutKey is the request's path and query with the key parameter taken out.
// The path always starts with a single slash: "//host" in a Location header
// would send the browser to another site.
func (g *Gate) withoutKey(u *url.URL) string {
	q := u.Query()
	for name := range q {
		if strings.EqualFold(name, g.title) {
			q.Del(name)
		}
	}
	target := (&url.URL{Path: "/" + strings.TrimLeft(u.Path, "/")}).EscapedPath()
	if enc := q.Encode(); enc != "" {
		target += "?" + enc
	}
	return target
}
