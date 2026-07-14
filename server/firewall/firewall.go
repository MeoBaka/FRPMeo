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

// Package firewall is a native access-control layer for frps: it decides
// whether an incoming user connection to a proxy is allowed, based on
// IP/CIDR + proxy + user rules. Rules are managed from the frps dashboard and
// persisted to a JSON file. No external service or plugin is involved.
package firewall

import (
	"encoding/json"
	"net"
	"os"
	"strings"
	"sync"
)

// Rule is a single access rule. Empty CIDR/Proxy/User matches anything.
// The first rule that matches (top to bottom) decides the verdict.
type Rule struct {
	ID     string `json:"id"`
	Action string `json:"action"` // "allow" | "deny"
	CIDR   string `json:"cidr"`   // "1.2.3.0/24", "1.2.3.4", "" or "*" = any
	Proxy  string `json:"proxy"`  // glob e.g. "rdp-*", "" or "*" = any
	User   string `json:"user"`   // glob, "" or "*" = any
	Note   string `json:"note"`
}

// RuleSet is the rule list plus the fallback policy applied when nothing matches.
type RuleSet struct {
	Default string `json:"default"` // "allow" | "deny"
	Rules   []Rule `json:"rules"`
}

// Firewall holds the active rule set and persists it to a file.
type Firewall struct {
	mu   sync.RWMutex
	path string
	rs   RuleSet
}

// New loads rules from path (or starts with a permissive default if absent).
func New(path string) (*Firewall, error) {
	f := &Firewall{path: path, rs: RuleSet{Default: "allow", Rules: []Rule{}}}
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	var rs RuleSet
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, err
	}
	f.rs = normalize(rs)
	return f, nil
}

func normalize(rs RuleSet) RuleSet {
	if rs.Rules == nil {
		rs.Rules = []Rule{}
	}
	if rs.Default == "" {
		rs.Default = "allow"
	}
	return rs
}

// Get returns a copy of the current rule set.
func (f *Firewall) Get() RuleSet {
	f.mu.RLock()
	defer f.mu.RUnlock()
	out := RuleSet{Default: f.rs.Default, Rules: make([]Rule, len(f.rs.Rules))}
	copy(out.Rules, f.rs.Rules)
	return out
}

// Set replaces the rule set and persists it to disk.
func (f *Firewall) Set(rs RuleSet) error {
	rs = normalize(rs)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rs = rs
	if f.path == "" {
		return nil
	}
	b, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// Allow decides whether a user connection is permitted. remoteAddr may be
// "ip:port"; proxy and user identify the target proxy and its owner.
func (f *Firewall) Allow(remoteAddr, proxy, user string) (bool, string) {
	ip := parseIP(remoteAddr)
	f.mu.RLock()
	defer f.mu.RUnlock()
	for _, r := range f.rs.Rules {
		if matchCIDR(r.CIDR, ip) && matchGlob(r.Proxy, proxy) && matchGlob(r.User, user) {
			return strings.ToLower(r.Action) == "allow", "rule " + r.ID
		}
	}
	def := f.rs.Default
	if def == "" {
		def = "allow"
	}
	return strings.ToLower(def) == "allow", "default " + def
}

func parseIP(remoteAddr string) net.IP {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func matchCIDR(cidr string, ip net.IP) bool {
	cidr = strings.TrimSpace(cidr)
	if cidr == "" || cidr == "*" {
		return true
	}
	if ip == nil {
		return false
	}
	if !strings.Contains(cidr, "/") {
		return ip.Equal(net.ParseIP(cidr))
	}
	_, n, err := net.ParseCIDR(cidr)
	if err != nil {
		return false
	}
	return n.Contains(ip)
}

// matchGlob supports a single '*' wildcard anywhere (prefix*, *suffix, a*b, *).
func matchGlob(pat, s string) bool {
	pat = strings.TrimSpace(pat)
	if pat == "" || pat == "*" {
		return true
	}
	if !strings.Contains(pat, "*") {
		return strings.EqualFold(pat, s)
	}
	parts := strings.Split(strings.ToLower(pat), "*")
	sl := strings.ToLower(s)
	if parts[0] != "" && !strings.HasPrefix(sl, parts[0]) {
		return false
	}
	if last := parts[len(parts)-1]; last != "" && !strings.HasSuffix(sl, last) {
		return false
	}
	pos := 0
	for _, p := range parts {
		if p == "" {
			continue
		}
		i := strings.Index(sl[pos:], p)
		if i < 0 {
			return false
		}
		pos += i + len(p)
	}
	return true
}
