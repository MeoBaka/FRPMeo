// Copyright 2017 fatedier, fatedier@gmail.com

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
	"compress/gzip"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/fatedier/frp/pkg/util/util"
)

type HTTPAuthMiddleware struct {
	user string

	passwd string

	authFailDelay time.Duration

	// onAuthFail, when set, is told about every rejected login. See
	// SetOnAuthFail.

	onAuthFail func(remoteAddr string)
}

func NewHTTPAuthMiddleware(user, passwd string) *HTTPAuthMiddleware {
	return &HTTPAuthMiddleware{
		user: user,

		passwd: passwd,
	}
}

func (authMid *HTTPAuthMiddleware) SetAuthFailDelay(delay time.Duration) *HTTPAuthMiddleware {
	authMid.authFailDelay = delay

	return authMid
}

// SetOnAuthFail installs a callback run for every rejected login, with the
// address it came from.

//

// A wrong password is the strongest signal this port produces. Nobody who

// belongs here gets it wrong repeatedly - they have it saved, or they look it

// up - so unlike a rate, which has to guess where normal ends, this needs no

// threshold to be meaningful. The delay above slows a guesser down; this is

// what lets somebody act on it.

func (authMid *HTTPAuthMiddleware) SetOnAuthFail(fn func(remoteAddr string)) *HTTPAuthMiddleware {
	authMid.onAuthFail = fn

	return authMid
}

func (authMid *HTTPAuthMiddleware) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqUser, reqPasswd, hasAuth := r.BasicAuth()

		if (authMid.user == "" && authMid.passwd == "") ||

			(hasAuth && util.ConstantTimeEqString(reqUser, authMid.user) &&

				util.ConstantTimeEqString(reqPasswd, authMid.passwd)) {

			next.ServeHTTP(w, r)
		} else {

			// Reported before the delay, not after: the point of the delay is
			// to hold this request open, and whoever is counting failures
			// should not be kept waiting alongside it.

			if authMid.onAuthFail != nil {
				authMid.onAuthFail(r.RemoteAddr)
			}

			if authMid.authFailDelay > 0 {
				time.Sleep(authMid.authFailDelay)
			}

			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)

			http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)

		}
	})
}

type HTTPGzipWrapper struct {
	h http.Handler
}

func (gw *HTTPGzipWrapper) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {

		gw.h.ServeHTTP(w, r)

		return

	}

	w.Header().Set("Content-Encoding", "gzip")

	gz := gzip.NewWriter(w)

	defer gz.Close()

	gzr := gzipResponseWriter{Writer: gz, ResponseWriter: w}

	gw.h.ServeHTTP(gzr, r)
}

func MakeHTTPGzipHandler(h http.Handler) http.Handler {
	return &HTTPGzipWrapper{
		h: h,
	}
}

type gzipResponseWriter struct {
	io.Writer

	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}
