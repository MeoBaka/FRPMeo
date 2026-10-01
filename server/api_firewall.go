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
	"fmt"
	"net/http"
	"strings"

	"github.com/fatedier/frp/server/firewall"
)

// GET /api/firewall - current firewall config (enabled, port switches, default,
// rules, provider).
func (svr *Service) apiFirewallGet(w http.ResponseWriter, _ *http.Request) {
	apiWriteJSON(w, http.StatusOK, svr.rc.Firewall.Snapshot())
}

// PUT /api/firewall - replace the whole config.
func (svr *Service) apiFirewallPut(w http.ResponseWriter, r *http.Request) {
	var body firewall.Config
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apiWriteJSON(w, http.StatusBadRequest, map[string]string{"error": "bad json"})
		return
	}
	if err := validateFirewallConfig(&body); err != nil {
		apiWriteJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	if err := svr.rc.Firewall.SetConfig(body); err != nil {
		apiWriteJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	apiWriteJSON(w, http.StatusOK, map[string]any{"ok": true})
}

// validateFirewallConfig rejects what would otherwise be quietly reinterpreted:
// a rule that compiles to matching nothing, a default that reads as deny, a
// provider mode that reads as off. Each is a setting that silently stops doing
// what its author meant, so it has to come back as an error while they are
// still looking at it. Rules missing an id are given one.
func validateFirewallConfig(c *firewall.Config) error {
	if err := firewall.ValidateDefault(c.Default); err != nil {
		return err
	}
	switch strings.ToLower(strings.TrimSpace(c.Provider.Mode)) {
	case "", "off", "frpcontrol", "custom":
	default:
		return fmt.Errorf("provider mode must be off, frpcontrol or custom, not %q", c.Provider.Mode)
	}
	for i := range c.Rules {
		a := strings.ToLower(strings.TrimSpace(c.Rules[i].Action))
		if a != "allow" && a != "deny" {
			return fmt.Errorf("rule action must be allow or deny, not %q", c.Rules[i].Action)
		}
		c.Rules[i].Action = a
		if err := firewall.ParsePortSpec(c.Rules[i].Port); err != nil {
			return err
		}
		if err := firewall.ValidateRuleTarget(c.Rules[i].CIDR); err != nil {
			return err
		}
		if c.Rules[i].ID == "" {
			c.Rules[i].ID = fwRandID()
		}
	}
	return nil
}

// GET /api/firewall/domains - what each domain named by a rule resolves to.
//
// A rule naming a name is only as good as its last lookup, and one that has
// been failing for a day is still matching whatever it resolved to yesterday.
// That is the right behavior - see domainResolver.refresh - but it has to be
// visible, or a rule quietly stops meaning what it says.
func (svr *Service) apiFirewallDomainsGet(w http.ResponseWriter, _ *http.Request) {
	apiWriteJSON(w, http.StatusOK, svr.rc.Firewall.DomainStatus())
}

// GET /api/firewall/provider - whether the reputation provider is answering,
// and since when. The one place to see an outage without reading the log.
func (svr *Service) apiFirewallProviderGet(w http.ResponseWriter, _ *http.Request) {
	apiWriteJSON(w, http.StatusOK, svr.rc.Firewall.ProviderStatus())
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
