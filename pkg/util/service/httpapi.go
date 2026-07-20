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

package service

import (
	"encoding/json"
	"net/http"
)

// RestartResponse is what the restart endpoint answers with.
type RestartResponse struct {
	OK         bool   `json:"ok"`
	Restarting bool   `json:"restarting"`
	Error      string `json:"error,omitempty"`
}

// RestartHandler restarts frp by exiting and letting the service manager start
// it again - typically called right after an update has replaced the binary.
//
// It must be registered behind the dashboard's authentication, like every other
// route that changes state: an unauthenticated caller could otherwise keep frp
// permanently restarting.
//
// When frp is not running under a service manager there is nothing to bring it
// back, so this refuses rather than exiting and leaving frp down.
func RestartHandler(logf func(format string, v ...any)) http.HandlerFunc {
	if logf == nil {
		logf = func(string, ...any) {}
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		if err := RestartSelf(); err != nil {
			logf("restart requested from %s but refused: %v", r.RemoteAddr, err)
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(RestartResponse{Error: err.Error()})
			return
		}

		logf("restart requested from %s, exiting for the service manager to restart", r.RemoteAddr)
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(RestartResponse{OK: true, Restarting: true})
		// Flush before the process goes away, so the caller learns the restart
		// was accepted rather than seeing the connection drop.
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
	}
}
