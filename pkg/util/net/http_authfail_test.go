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

package net

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func authTestHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}

// A wrong password is the clearest evidence this port produces, so somebody has
// to be told about it.
func TestOnAuthFailReportsRejectedLogins(t *testing.T) {
	var (
		mu   sync.Mutex
		seen []string
	)
	mid := NewHTTPAuthMiddleware("admin", "secret").
		SetOnAuthFail(func(remoteAddr string) {
			mu.Lock()
			seen = append(seen, remoteAddr)
			mu.Unlock()
		}).
		Middleware(authTestHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "wrong")
	req.RemoteAddr = "9.9.9.9:5000"
	rec := httptest.NewRecorder()
	mid.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 1 || seen[0] != "9.9.9.9:5000" {
		t.Fatalf("reported %v, want one entry for 9.9.9.9:5000", seen)
	}
}

// The hook must stay silent for people who got it right, or the thing counting
// failures would ban everybody.
func TestOnAuthFailNotCalledOnSuccess(t *testing.T) {
	var called int
	mid := NewHTTPAuthMiddleware("admin", "secret").
		SetOnAuthFail(func(string) { called++ }).
		Middleware(authTestHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "secret")
	rec := httptest.NewRecorder()
	mid.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if called != 0 {
		t.Fatalf("hook fired %d times for a correct password", called)
	}
}

// A server with no credentials configured lets everybody through, so there is
// no such thing as a failure to report.
func TestOnAuthFailNotCalledWhenAuthIsDisabled(t *testing.T) {
	var called int
	mid := NewHTTPAuthMiddleware("", "").
		SetOnAuthFail(func(string) { called++ }).
		Middleware(authTestHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	mid.ServeHTTP(rec, req)

	if called != 0 {
		t.Fatalf("hook fired %d times with auth switched off", called)
	}
}

// Reported before the delay, not after: the delay exists to hold the request
// open, and whoever is counting failures should not be held open with it.
func TestOnAuthFailReportedBeforeTheDelay(t *testing.T) {
	reported := make(chan time.Time, 1)
	mid := NewHTTPAuthMiddleware("admin", "secret").
		SetAuthFailDelay(300 * time.Millisecond).
		SetOnAuthFail(func(string) { reported <- time.Now() }).
		Middleware(authTestHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "wrong")
	start := time.Now()

	go mid.ServeHTTP(httptest.NewRecorder(), req)

	select {
	case at := <-reported:
		if d := at.Sub(start); d > 150*time.Millisecond {
			t.Fatalf("hook fired after %v, so it is waiting out the delay", d)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("hook did not fire before the delay elapsed")
	}
}

// Nothing configured must not panic - the hook is optional.
func TestAuthMiddlewareWithoutHook(t *testing.T) {
	mid := NewHTTPAuthMiddleware("admin", "secret").Middleware(authTestHandler())

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.SetBasicAuth("admin", "wrong")
	rec := httptest.NewRecorder()
	mid.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", rec.Code)
	}
}
