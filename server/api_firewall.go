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
	"encoding/json"
	"net/http"

	"github.com/fatedier/frp/server/firewall"
)

// GET /api/firewall - current anti-bot config (antiAttacker, kernelBan).
func (svr *Service) apiFirewallGet(w http.ResponseWriter, _ *http.Request) {
	apiWriteJSON(w, http.StatusOK, svr.rc.Firewall.Snapshot())
}

// PUT /api/firewall - replace antiAttacker/kernelBan.
func (svr *Service) apiFirewallPut(w http.ResponseWriter, r *http.Request) {
	var body firewall.Config
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiWriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if err := svr.rc.Firewall.SetConfig(body); err != nil {
		apiWriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	apiWriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func apiWriteJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// GET /api/firewall/status - what the anti-bot layer is doing right now:
// whether the attack state is on, how many sources each layer is tracking, and
// who is currently banned.
//
// Separate from the config endpoint because it answers a different question and
// changes on a different timescale: the settings are edited by hand now and
// then, this moves every second.
func (svr *Service) apiFirewallStatusGet(w http.ResponseWriter, _ *http.Request) {
	apiWriteJSON(w, http.StatusOK, svr.rc.Firewall.AntiAttackerStatus())
}

// DELETE /api/firewall/bans - lift every ban and forget every strike.
func (svr *Service) apiFirewallBansDelete(w http.ResponseWriter, _ *http.Request) {
	svr.rc.Firewall.ClearAntiAttackerBans()
	apiWriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}
