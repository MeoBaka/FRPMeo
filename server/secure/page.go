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
	"fmt"
	"html"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/fatedier/frp/pkg/util/vhost"
)

// answer is a reply frps writes itself, without the backend: a login page, a
// confirmation, a refusal or a redirect. It goes out over a raw connection, an
// http.ResponseWriter or a vhost refusal, depending on where the request came
// in.
type answer struct {
	status      int
	contentType string
	body        string
	header      http.Header
}

func (a answer) headers() http.Header {
	h := make(http.Header, len(a.header)+2)
	maps.Copy(h, a.header)
	if a.contentType != "" {
		h.Set("Content-Type", a.contentType)
	}
	// Nothing here is worth caching, least of all a page saying you are in.
	h.Set("Cache-Control", "no-store")
	return h
}

// write sends a over a connection frps is reading requests from itself.
func (a answer) write(w io.Writer, req *http.Request) error {
	resp := &http.Response{
		StatusCode:    a.status,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        a.headers(),
		Body:          io.NopCloser(strings.NewReader(a.body)),
		ContentLength: int64(len(a.body)),
		Close:         true,
		Request:       req,
	}
	return resp.Write(w)
}

// serve sends a through an http.ResponseWriter.
func (a answer) serve(rw http.ResponseWriter) {
	maps.Copy(rw.Header(), a.headers())
	rw.WriteHeader(a.status)
	_, _ = io.WriteString(rw, a.body)
}

// decision turns a into the refusal of an http proxy's admission check.
func (a answer) decision() vhost.AllowDecision {
	d := vhost.AllowDecision{StatusCode: a.status, Header: a.headers()}
	if a.body != "" {
		d.Body = []byte(a.body)
	}
	return d
}

func wantsHTML(req *http.Request) bool {
	return strings.Contains(req.Header.Get("Accept"), "text/html")
}

// basicChallenge is what makes a browser show its sign-in prompt. Browsers keep
// the credentials per site and realm; Chrome shows only the site, Firefox the
// realm too.
const basicChallenge = `Basic realm="Secure access", charset="UTF-8"`

// challenge turns a into the answer that asks for basic credentials: 401 with
// WWW-Authenticate. a's body is what a visitor who cancels the prompt sees.
func challenge(a answer) answer {
	h := make(http.Header, len(a.header)+1)
	maps.Copy(h, a.header)
	h.Set("WWW-Authenticate", basicChallenge)
	a.header = h
	a.status = http.StatusUnauthorized
	return a
}

// loginPage asks for the key. With basic on, a browser shows its sign-in
// prompt for it, and the page is what it shows if the visitor cancels. The
// page's own form posts the key as a field when form is on, and puts it in the
// query - a link - when only link is.
func (g *Gate) loginPage(req *http.Request) answer {
	a := g.loginBody(req)
	if g.basic {
		a = challenge(a)
	}
	return a
}

func (g *Gate) loginBody(req *http.Request) answer {
	if !wantsHTML(req) {
		return textAnswer(http.StatusUnauthorized, g.howTo())
	}
	method := ""
	switch {
	case g.form:
		method = "post"
	case g.link:
		method = "get"
	}
	if method == "" {
		if g.basic {
			return htmlAnswer(http.StatusUnauthorized, "Secure access",
				`<p>Tải lại trang rồi đăng nhập: tên đăng nhập là title, mật khẩu là key.<br>`+
					`Reload the page and sign in with the title as the username and the key as the password.</p>`)
		}
		return textAnswer(http.StatusUnauthorized, g.howTo())
	}
	form := `<p>Nhập key để mở khóa.<br>Enter the key to unlock.</p>` +
		`<form method="` + method + `">` +
		`<input type="password" name="` + html.EscapeString(g.title) + `" placeholder="key" autofocus autocomplete="current-password">` +
		`<button type="submit">Mở khóa / Unlock</button></form>`
	return htmlAnswer(http.StatusUnauthorized, "Secure access", form)
}

// howTo tells a client that is not a browser how this proxy takes the key.
func (g *Gate) howTo() string {
	var ways []string
	if g.link || g.header || g.form || g.json {
		ways = append(ways, fmt.Sprintf("as %q", g.title))
	}
	if g.basic {
		ways = append(ways, "by basic auth with the title as the username")
	}
	if g.bearer {
		ways = append(ways, "as Authorization: Bearer <key>")
	}
	if len(ways) == 0 {
		return "secure access: this address needs the key\n"
	}
	return "secure access: send the key " + strings.Join(ways, ", or ") + "\n"
}

// wrongKey answers a key that did not match. Basic credentials are asked for
// again, the way any site answers a wrong password.
func (g *Gate) wrongKey(req *http.Request, v via) answer {
	a := wrongKeyPage(req)
	if v == viaBasic {
		a = challenge(a)
	}
	return a
}

func wrongKeyPage(req *http.Request) answer {
	if !wantsHTML(req) {
		return textAnswer(http.StatusForbidden, "wrong key\n")
	}
	return htmlAnswer(http.StatusForbidden, "Sai key / Wrong key",
		`<p>Key không đúng. Thử sai nhiều lần sẽ bị chặn một thời gian.<br>`+
			`The key is wrong. Repeated wrong keys get your address banned for a while.</p>`)
}

// unlockedPage confirms an unlock. pageLink adds a link to the page the request
// asked for, without the key, for a port whose backend may be that website.
func (g *Gate) unlockedPage(req *http.Request, ip netip.Addr, pageLink bool) answer {
	d := humanDuration(g.unlockTTL)
	if !wantsHTML(req) {
		return textAnswer(http.StatusOK, fmt.Sprintf("unlocked %s for %s\n", ip, d))
	}
	who := html.EscapeString(ip.String())
	inner := `<p>IP ` + who + ` được vào trong ` + d + `. Bạn có thể kết nối ngay.<br>` +
		who + ` may connect for ` + d + `. You can connect now.</p>`
	if pageLink {
		inner += `<p><a href="` + html.EscapeString(g.withoutKey(req.URL)) + `">Mở trang web / Open the website</a></p>`
	}
	return htmlAnswer(http.StatusOK, "Đã mở khóa / Unlocked", inner)
}

func textAnswer(status int, body string) answer {
	return answer{status: status, contentType: "text/plain; charset=utf-8", body: body}
}

// htmlAnswer wraps inner, which must already be escaped, in a small page.
func htmlAnswer(status int, title, inner string) answer {
	return answer{
		status:      status,
		contentType: "text/html; charset=utf-8",
		body:        pageHead + html.EscapeString(title) + pageMiddle + "<h1>" + html.EscapeString(title) + "</h1>" + inner + pageTail,
	}
}

const pageHead = `<!doctype html><html><head><meta charset="utf-8">` +
	`<meta name="viewport" content="width=device-width,initial-scale=1"><title>`

const pageMiddle = `</title><style>` +
	`body{font-family:system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;background:#f4f4f5;color:#18181b}` +
	`main{background:#fff;padding:28px;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08);width:100%;max-width:360px;box-sizing:border-box}` +
	`h1{font-size:18px;margin:0 0 12px}p{font-size:14px;line-height:1.5;margin:0 0 16px}` +
	`input{width:100%;box-sizing:border-box;padding:10px;font-size:15px;border:1px solid #d4d4d8;border-radius:8px;margin-bottom:12px}` +
	`button{width:100%;padding:10px;font-size:15px;border:0;border-radius:8px;background:#2563eb;color:#fff;cursor:pointer}` +
	`@media (prefers-color-scheme:dark){body{background:#18181b;color:#f4f4f5}main{background:#27272a}` +
	`input{background:#18181b;color:#f4f4f5;border-color:#52525b}}` +
	`</style></head><body><main>`

const pageTail = `</main></body></html>`

// humanDuration writes d the way a person would: 12h, 1h30m, 45s.
func humanDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := d / time.Hour
	m := (d % time.Hour) / time.Minute
	s := (d % time.Minute) / time.Second
	var b strings.Builder
	if h > 0 {
		fmt.Fprintf(&b, "%dh", h)
	}
	if m > 0 {
		fmt.Fprintf(&b, "%dm", m)
	}
	if s > 0 || b.Len() == 0 {
		fmt.Fprintf(&b, "%ds", s)
	}
	return b.String()
}
