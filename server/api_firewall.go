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

package server

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/fatedier/frp/server/firewall"
)

// GET /api/firewall - return the current rule set.
func (svr *Service) apiFirewallGet(w http.ResponseWriter, _ *http.Request) {
	apiWriteJSON(w, http.StatusOK, svr.rc.Firewall.Get())
}

// PUT /api/firewall - replace the rule set (and persist it).
func (svr *Service) apiFirewallPut(w http.ResponseWriter, r *http.Request) {
	var rs firewall.RuleSet
	if err := json.NewDecoder(r.Body).Decode(&rs); err != nil {
		apiWriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if rs.Default != "allow" && rs.Default != "deny" {
		rs.Default = "allow"
	}
	for i := range rs.Rules {
		a := strings.ToLower(rs.Rules[i].Action)
		if a != "allow" && a != "deny" {
			apiWriteJSON(w, http.StatusBadRequest, map[string]string{"error": "rule action must be allow or deny"})
			return
		}
		rs.Rules[i].Action = a
		if rs.Rules[i].ID == "" {
			rs.Rules[i].ID = fwRandID()
		}
	}
	if err := svr.rc.Firewall.Set(rs); err != nil {
		apiWriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	apiWriteJSON(w, http.StatusOK, map[string]any{"ok": true, "rules": len(rs.Rules)})
}

func apiWriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fwRandID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
