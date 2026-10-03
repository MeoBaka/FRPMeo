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
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// Where in an HTTP request a key can be, for the methods that are on.

// via is the way a key arrived, where that changes how it is answered.
type via int

const (
	// viaHeader is the title header or a bearer token: sent with every
	// request rather than once to unlock.
	viaHeader via = iota

	// viaBasic is basic credentials, also sent with every request, and asked
	// for again when wrong - the way any site answers a wrong password.
	viaBasic

	// viaLink is the query of a link.
	viaLink

	// viaBody is a form or JSON body.
	viaBody
)

// presented is a key as a request carried it.
type presented struct {
	// title is what the key came under. Empty for a bearer token, which names
	// none and is matched against every login.
	title string
	key   string
	via   via
}

// valid reports whether p is one of the logins.
func (g *Gate) valid(p presented) bool {
	return g.matches(p.title, p.key)
}

// keyFromRequest finds a key wherever the enabled methods allow it in an
// unlock request: a header, a bearer token, basic credentials, the query
// (link), or a form or JSON body.
func (g *Gate) keyFromRequest(req *http.Request) (presented, bool) {
	if p, ok := g.everyRequestKey(req); ok {
		return p, true
	}
	if g.link {
		if p, ok := g.queryKey(req); ok {
			return p, true
		}
	}
	return g.bodyKey(req)
}

// everyRequestKey finds a key of the kind a client sends with every request
// rather than once to unlock: a title header, a bearer token, or basic
// credentials naming a title. Basic credentials for any other username are
// somebody else's - the backend's own sign-in, say - and are left alone.
func (g *Gate) everyRequestKey(req *http.Request) (presented, bool) {
	if g.header {
		for _, t := range g.titles {
			if key := req.Header.Get(t); key != "" {
				return presented{title: t, key: key, via: viaHeader}, true
			}
		}
	}
	if g.bearer {
		if key, ok := bearerToken(req); ok {
			return presented{key: key, via: viaHeader}, true
		}
	}
	return g.basicKey(req)
}

// basicKey finds basic credentials whose username is one of the titles.
func (g *Gate) basicKey(req *http.Request) (presented, bool) {
	if !g.basic {
		return presented{}, false
	}
	user, pass, ok := req.BasicAuth()
	if !ok {
		return presented{}, false
	}
	title, ok := g.titleOf(user)
	if !ok {
		return presented{}, false
	}
	return presented{title: title, key: pass, via: viaBasic}, true
}

// queryKey finds a key in the URL query: a parameter named after a title, or
// the title and key fields of frps' own sign-in form.
func (g *Gate) queryKey(req *http.Request) (presented, bool) {
	p, ok := g.fieldsKey(req.URL.Query())
	p.via = viaLink
	return p, ok
}

// bodyKey looks for a key in a JSON body (json) or a form body (form): a field
// named after a title, or the title and key fields of frps' sign-in form.
func (g *Gate) bodyKey(req *http.Request) (presented, bool) {
	if req.Body == nil {
		return presented{}, false
	}
	isJSON := strings.HasPrefix(req.Header.Get("Content-Type"), "application/json")
	if (isJSON && !g.json) || (!isJSON && !g.form) {
		return presented{}, false
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxKnockBody))
	if err != nil || len(body) == 0 {
		return presented{}, false
	}
	fields := url.Values{}
	if isJSON {
		var obj map[string]any
		if json.Unmarshal(body, &obj) != nil {
			return presented{}, false
		}
		for name, v := range obj {
			if s, ok := v.(string); ok {
				fields.Set(name, s)
			}
		}
	} else {
		// A form, or a body sent with no type at all.
		if fields, err = url.ParseQuery(string(body)); err != nil {
			return presented{}, false
		}
	}
	p, ok := g.fieldsKey(fields)
	p.via = viaBody
	return p, ok
}

// fieldsKey finds a key among named values - a query or a body. The sign-in
// form's pair counts only whole: a title with no key is nobody's login.
func (g *Gate) fieldsKey(fields url.Values) (presented, bool) {
	var formTitle, formKey string
	for name, values := range fields {
		if len(values) == 0 {
			continue
		}
		switch {
		case strings.EqualFold(name, v1.SecureFormTitleField):
			formTitle = values[0]
		case strings.EqualFold(name, v1.SecureFormKeyField):
			formKey = values[0]
		default:
			if t, ok := g.titleOf(name); ok {
				return presented{title: t, key: values[0]}, true
			}
		}
	}
	if formTitle != "" && formKey != "" {
		return presented{title: strings.TrimSpace(formTitle), key: formKey}, true
	}
	return presented{}, false
}

// ownsAuthorization reports whether the request's Authorization header carries
// one of this proxy's logins, and so is frps' to take out rather than the
// backend's.
func (g *Gate) ownsAuthorization(req *http.Request) bool {
	if g.bearer {
		if key, ok := bearerToken(req); ok {
			return g.matches("", key)
		}
	}
	if p, ok := g.basicKey(req); ok {
		return g.valid(p)
	}
	return false
}

// bearerToken reads "Authorization: Bearer <token>".
func bearerToken(req *http.Request) (string, bool) {
	return parseBearer(req.Header.Get("Authorization"))
}

func parseBearer(value string) (string, bool) {
	scheme, token, ok := strings.Cut(strings.TrimSpace(value), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	token = strings.TrimSpace(token)
	return token, token != ""
}

// withoutKeyHeaders is a header block with the headers that carried a key
// taken out: every title header, and an Authorization header holding one of
// this proxy's bearer tokens. A continuation line goes with the header it
// continues.
func (g *Gate) withoutKeyHeaders(raw []byte) []byte {
	lines := bytes.Split(bytes.TrimSuffix(raw, []byte("\r\n\r\n")), []byte("\r\n"))
	out := make([]byte, 0, len(raw))
	dropping := false
	for i, line := range lines {
		if i > 0 {
			continued := len(line) > 0 && (line[0] == ' ' || line[0] == '\t')
			if !continued {
				dropping = g.carriesKey(line)
			}
			if dropping {
				continue
			}
		}
		out = append(out, line...)
		out = append(out, "\r\n"...)
	}
	return append(out, "\r\n"...)
}

// carriesKey reports whether a header line is one withoutKeyHeaders removes.
func (g *Gate) carriesKey(line []byte) bool {
	name, value, ok := bytes.Cut(line, []byte(":"))
	if !ok {
		return false
	}
	name = bytes.TrimSpace(name)
	if _, ok := g.titleOf(string(name)); ok {
		return true
	}
	if !bytes.EqualFold(name, []byte("Authorization")) {
		return false
	}
	key, ok := parseBearer(string(value))
	return ok && g.matches("", key)
}
