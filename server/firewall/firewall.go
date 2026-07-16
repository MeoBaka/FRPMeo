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

// Package firewall is a native access-control layer for frps. A user connection
// is decided (only when the firewall is enabled) in this order:
//
//  1. Manual rules - ordered allow/deny by IP/CIDR + proxy + user (first match).
//  2. Reputation provider (optional) - for still-unknown source IPs, ask an
//     external blacklist API whether the IP is blocked. This can be an
//     FRPControl service (frps knows its API - you only supply URL + key) or a
//     fully custom API (configurable URL/method/headers + JSON path). Results
//     are cached per IP. frps never hosts the blacklist itself.
//  3. Default policy.
//
// IPv4, IPv6 and CIDR are supported.
package firewall

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Rule is a manual, ordered allow/deny rule. Empty CIDR/Proxy/User matches any.
type Rule struct {
	ID        string `json:"id"`
	Action    string `json:"action"` // "allow" | "deny"
	CIDR      string `json:"cidr"`   // "1.2.3.0/24", "::1", "1.2.3.4", "" or "*" = any
	Proxy     string `json:"proxy"`  // glob, "" or "*" = any
	User      string `json:"user"`   // glob, "" or "*" = any
	Note      string `json:"note,omitempty"`
	ExpiresAt int64  `json:"expiresAt,omitempty"` // unix sec, 0 = permanent
}

// ProviderConfig selects the external blacklist provider frps consults.
//
//	mode "off"        -> no external check (manual rules + default only)
//	mode "frpcontrol" -> query an FRPControl service; only FRPControlURL +
//	                     FRPControlAPIKey are needed (frps knows the format:
//	                     POST {url}/api/fw/check {"ips":["<ip>"]} with X-API-Key,
//	                     reading results.0.blacklisted).
//	mode "custom"     -> query any API using URL/Method/Body/Headers/BlockedPath.
type ProviderConfig struct {
	Mode string `json:"mode"`

	// frpcontrol mode
	FRPControlURL    string `json:"frpControlURL,omitempty"`
	FRPControlAPIKey string `json:"frpControlAPIKey,omitempty"`

	// custom mode ("{ip}" is substituted in URL / Body / BlockedPath)
	URL         string            `json:"url,omitempty"`
	Method      string            `json:"method,omitempty"` // GET (default) | POST
	Body        string            `json:"body,omitempty"`
	Headers     map[string]string `json:"headers,omitempty"`
	BlockedPath string            `json:"blockedPath,omitempty"` // e.g. results.0.blacklisted

	// common
	CacheTTLSec int  `json:"cacheTTLSec,omitempty"` // per-ip cache (default 300)
	TimeoutMs   int  `json:"timeoutMs,omitempty"`   // request timeout (default 800)
	FailOpen    bool `json:"failOpen"`              // on error: allow (true) or block (false)
	InsecureTLS bool `json:"insecureTLS,omitempty"` // skip TLS verify (self-signed)
}

// effective resolves frpcontrol into a concrete custom request.
func (p ProviderConfig) effective() ProviderConfig {
	if p.Mode != "frpcontrol" {
		return p
	}
	return ProviderConfig{
		Mode:        "custom",
		URL:         strings.TrimRight(p.FRPControlURL, "/") + "/api/fw/check",
		Method:      "POST",
		Body:        `{"ips":["{ip}"]}`,
		Headers:     map[string]string{"X-API-Key": p.FRPControlAPIKey},
		BlockedPath: "results.0.blacklisted",
		CacheTTLSec: p.CacheTTLSec,
		TimeoutMs:   p.TimeoutMs,
		FailOpen:    p.FailOpen,
		InsecureTLS: p.InsecureTLS,
	}
}

type state struct {
	Enabled     *bool          `json:"enabled,omitempty"` // nil = enabled
	ControlPort bool           `json:"controlPort"`
	Default     string         `json:"default"`
	Rules       []Rule         `json:"rules"`
	Provider    ProviderConfig `json:"provider"`
}

// Snapshot is returned to the dashboard.
type Snapshot struct {
	Enabled     bool           `json:"enabled"`
	ControlPort bool           `json:"controlPort"`
	Default     string         `json:"default"`
	Rules       []Rule         `json:"rules"`
	Provider    ProviderConfig `json:"provider"`
}

type repEntry struct {
	blocked bool
	exp     int64
}

// Firewall holds live state and persists it to a JSON file.
type Firewall struct {
	mu    sync.RWMutex
	path  string
	nowFn func() int64

	enabled     bool
	controlPort bool
	def         string
	rules       []Rule
	provider    ProviderConfig
	client      *http.Client

	repMu    sync.Mutex
	repCache map[string]repEntry
}

// New loads firewall state from path and starts a background expiry sweeper.
func New(path string) (*Firewall, error) {
	f := &Firewall{
		path:     path,
		nowFn:    func() int64 { return time.Now().Unix() },
		enabled:  true,
		def:      "allow",
		repCache: make(map[string]repEntry),
	}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		var s state
		if err := json.Unmarshal(b, &s); err != nil {
			return nil, err
		}
		f.enabled = s.Enabled == nil || *s.Enabled
		f.controlPort = s.ControlPort
		f.def = orDefault(strings.ToLower(s.Default), "allow")
		f.rules = s.Rules
		f.provider = s.Provider
	case os.IsNotExist(err):
	default:
		return nil, err
	}
	if f.provider.Mode == "" {
		f.provider.Mode = "off"
	}
	f.mu.Lock()
	f.pruneLocked()
	f.buildClientLocked()
	_ = f.saveLocked()
	f.mu.Unlock()

	go f.sweep()
	return f, nil
}

func (f *Firewall) sweep() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()
	for range t.C {
		f.mu.Lock()
		if f.pruneLocked() {
			_ = f.saveLocked()
		}
		f.mu.Unlock()
	}
}

// AllowControl decides whether an frpc client may connect to the frps control
// port at all (checked on accept, before login). It is opt-in via the
// controlPort toggle: protecting the control port with a deny-by-default policy
// locks out every client, so existing setups keep the old behavior until asked.
// Only IP-scoped rules can match here - there is no proxy or user yet.
func (f *Firewall) AllowControl(remoteAddr string) (bool, string) {
	f.mu.RLock()
	on := f.enabled && f.controlPort
	f.mu.RUnlock()
	if !on {
		return true, "control port not protected"
	}
	return f.Allow(remoteAddr, "", "")
}

// Allow decides whether a user connection is permitted.
func (f *Firewall) Allow(remoteAddr, proxy, user string) (bool, string) {
	f.mu.RLock()
	if !f.enabled {
		f.mu.RUnlock()
		return true, "firewall disabled"
	}
	now := f.nowFn()
	ip := parseIP(remoteAddr)

	// 1) manual rules, in order
	for _, r := range f.rules {
		if r.ExpiresAt != 0 && r.ExpiresAt <= now {
			continue
		}
		if matchCIDR(r.CIDR, ip) && matchGlob(r.Proxy, proxy) && matchGlob(r.User, user) {
			allow := strings.ToLower(r.Action) == "allow"
			f.mu.RUnlock()
			return allow, "rule " + r.ID
		}
	}
	provider := f.provider
	client := f.client
	def := f.def
	f.mu.RUnlock()

	// 2) external reputation provider for unknown IPs
	if (provider.Mode == "frpcontrol" || provider.Mode == "custom") && ip != nil {
		if f.checkExternal(ip.String(), provider.effective(), client) {
			return false, "reputation"
		}
	}
	// 3) default policy
	return def == "allow", "default " + def
}

// checkExternal returns whether ip is blocked according to the provider,
// caching per ip. On error it honors FailOpen (fail-closed = blocked).
func (f *Firewall) checkExternal(ipStr string, p ProviderConfig, client *http.Client) bool {
	now := f.nowFn()
	f.repMu.Lock()
	if e, ok := f.repCache[ipStr]; ok && e.exp > now {
		f.repMu.Unlock()
		return e.blocked
	}
	f.repMu.Unlock()

	blocked, err := queryProvider(ipStr, p, client)
	ttl := int64(p.CacheTTLSec)
	if ttl <= 0 {
		ttl = 300
	}
	if err != nil {
		blocked = !p.FailOpen // fail-closed by default
		ttl = 10              // don't hammer a failing provider
	}
	f.repMu.Lock()
	f.repCache[ipStr] = repEntry{blocked: blocked, exp: now + ttl}
	f.repMu.Unlock()
	return blocked
}

func queryProvider(ipStr string, p ProviderConfig, client *http.Client) (bool, error) {
	if p.URL == "" || p.BlockedPath == "" {
		return false, errors.New("provider url/blockedPath not set")
	}
	method := strings.ToUpper(strings.TrimSpace(p.Method))
	if method == "" {
		method = "GET"
	}
	url := strings.ReplaceAll(p.URL, "{ip}", ipStr)
	var body io.Reader
	if method == "POST" {
		body = strings.NewReader(strings.ReplaceAll(p.Body, "{ip}", ipStr))
	}
	timeout := time.Duration(p.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 800 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return false, err
	}
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("provider status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, err
	}
	var data any
	if err := json.Unmarshal(raw, &data); err != nil {
		return false, err
	}
	return truthy(extractPath(data, p.BlockedPath, ipStr)), nil
}

// extractPath walks a dot path (keys + numeric array indices, "{ip}" allowed).
func extractPath(data any, path, ip string) any {
	for seg := range strings.SplitSeq(path, ".") {
		if seg == "" {
			continue
		}
		seg = strings.ReplaceAll(seg, "{ip}", ip)
		switch v := data.(type) {
		case map[string]any:
			data = v[seg]
		case []any:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(v) {
				return nil
			}
			data = v[idx]
		default:
			return nil
		}
	}
	return data
}

func truthy(v any) bool {
	switch x := v.(type) {
	case bool:
		return x
	case float64:
		return x != 0
	case string:
		s := strings.ToLower(x)
		return s == "true" || s == "1" || s == "yes"
	}
	return false
}

// Snapshot returns the current state for the dashboard.
func (f *Firewall) Snapshot() Snapshot {
	f.mu.RLock()
	defer f.mu.RUnlock()
	rules := make([]Rule, len(f.rules))
	copy(rules, f.rules)
	return Snapshot{Enabled: f.enabled, ControlPort: f.controlPort, Default: f.def, Rules: rules, Provider: f.provider}
}

// SetConfig replaces enabled/controlPort/default/rules/provider.
func (f *Firewall) SetConfig(enabled, controlPort bool, def string, rules []Rule, provider ProviderConfig) error {
	def = strings.ToLower(def)
	if def != "allow" && def != "deny" {
		def = "allow"
	}
	if provider.Mode == "" {
		provider.Mode = "off"
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = enabled
	f.controlPort = controlPort
	f.def = def
	f.rules = rules
	f.provider = provider
	f.buildClientLocked()
	f.repMu.Lock()
	f.repCache = make(map[string]repEntry)
	f.repMu.Unlock()
	return f.saveLocked()
}

// --- internals (call with f.mu held) ---

func (f *Firewall) buildClientLocked() {
	tr := &http.Transport{}
	if f.provider.InsecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 - opt-in for self-signed providers
	}
	f.client = &http.Client{Transport: tr}
}

func (f *Firewall) pruneLocked() bool {
	now := f.nowFn()
	changed := false
	rules := f.rules[:0]
	for _, r := range f.rules {
		if r.ExpiresAt != 0 && r.ExpiresAt <= now {
			changed = true
			continue
		}
		rules = append(rules, r)
	}
	f.rules = rules
	return changed
}

func (f *Firewall) saveLocked() error {
	if f.path == "" {
		return nil
	}
	enabled := f.enabled
	s := state{Enabled: &enabled, ControlPort: f.controlPort, Default: f.def, Rules: f.rules, Provider: f.provider}
	if s.Rules == nil {
		s.Rules = []Rule{}
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	tmp := f.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, f.path)
}

// --- helpers ---

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
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
