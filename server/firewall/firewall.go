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
//  1. Manual rules - ordered allow/deny by IP/CIDR + destination port (first
//     match).
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
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/util/log"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

// Rule is a manual, ordered allow/deny rule. An empty CIDR or Port matches any.
//
// Rules match on the frps-side port a connection arrived on rather than on the
// proxy name or owner: a port is what a client actually dials and it belongs to
// one proxy at a time, while a proxy can come back under a different name and
// silently take its old rule out of play.
type Rule struct {
	ID     string `json:"id"`
	Action string `json:"action"` // "allow" | "deny"
	CIDR   string `json:"cidr"`   // "1.2.3.0/24", "::1", "1.2.3.4", "" or "*" = any
	// Port is a Windows-firewall style spec: "6000", "6000-6010",
	// "80,443,7000-7010", or "" / "*" / "all" for any port.
	Port      string `json:"port"`
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

// compiledRule is a Rule with its CIDR and port spec already parsed.
//
// Rules change rarely and are matched on every user connection - on every
// packet for udp - so the parsing happens when the rule arrives rather than
// when traffic does. What is left on the hot path is a prefix comparison and a
// few integer comparisons, and nothing on it reaches the heap.
type compiledRule struct {
	Rule

	allow   bool
	anyCIDR bool
	prefix  netip.Prefix
	anyPort bool
	ports   []portRange
	// reason is what Allow reports when this rule decides, built here so that
	// deciding does not have to build a string.
	reason string
	// never marks a CIDR that does not parse. Such a rule matches nothing,
	// which is what the old string matcher did with it as well: a rule that
	// visibly does nothing beats a deny that quietly widens to everything.
	never bool
}

// portRange is one entry of a compiled port spec, inclusive at both ends.
type portRange struct{ lo, hi int }

func compileRules(rules []Rule) []compiledRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]compiledRule, 0, len(rules))
	for _, r := range rules {
		out = append(out, compileRule(r))
	}
	return out
}

func compileRule(r Rule) compiledRule {
	c := compiledRule{
		Rule:   r,
		allow:  strings.EqualFold(strings.TrimSpace(r.Action), "allow"),
		reason: "rule " + r.ID,
	}

	cidr := strings.TrimSpace(r.CIDR)
	switch {
	case cidr == "" || cidr == "*":
		c.anyCIDR = true
	case strings.Contains(cidr, "/"):
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			c.never = true
			break
		}
		if a := p.Addr(); a.Is4In6() && p.Bits() >= 96 {
			// "::ffff:1.2.3.0/120" names an IPv4 network. Hold it in the form
			// addresses are matched in, or it would match none of them.
			p = netip.PrefixFrom(a.Unmap(), p.Bits()-96)
		}
		c.prefix = p.Masked()
	default:
		addr, err := netip.ParseAddr(cidr)
		if err != nil {
			c.never = true
			break
		}
		addr = addr.Unmap()
		c.prefix = netip.PrefixFrom(addr, addr.BitLen())
	}

	c.ports, c.anyPort = compilePorts(r.Port)
	return c
}

// compilePorts reads a port spec into the ranges it names. A malformed entry is
// dropped rather than widened, so a spec naming nothing valid matches nothing -
// see matchPort's old contract, which this keeps.
func compilePorts(spec string) (ranges []portRange, any bool) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" || strings.EqualFold(spec, "all") {
		return nil, true
	}
	for part := range strings.SplitSeq(spec, ",") {
		if lo, hi, ok := parsePortRange(part); ok {
			ranges = append(ranges, portRange{lo: lo, hi: hi})
		}
	}
	return ranges, false
}

func (c *compiledRule) match(ip netip.Addr, port int) bool {
	if c.never {
		return false
	}
	if !c.anyCIDR && (!ip.IsValid() || !c.prefix.Contains(ip)) {
		return false
	}
	return c.anyPort || matchRanges(c.ports, port)
}

func matchRanges(ranges []portRange, port int) bool {
	for _, r := range ranges {
		if port >= r.lo && port <= r.hi {
			return true
		}
	}
	return false
}

// plainRules unwraps compiled rules back into what the dashboard and the state
// file speak in.
func plainRules(rules []compiledRule) []Rule {
	out := make([]Rule, len(rules))
	for i := range rules {
		out[i] = rules[i].Rule
	}
	return out
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
	rules       []compiledRule
	provider    ProviderConfig
	client      *http.Client

	// selfProviderPort is set when the provider URL points back at this frps,
	// e.g. the panel is only reachable through a tunnel frps itself serves.
	// Asking the provider then means dialing our own public port, which is a
	// new user connection, which asks the provider again - so the provider
	// step is skipped for our own calls. 0 when the provider is elsewhere.
	// See resolveSelfProvider.
	selfProviderPort int
	// localIPs are this host's own addresses, resolved when the config is set
	// rather than per connection.
	localIPs map[string]bool

	repMu       sync.Mutex
	repCache    map[string]repEntry
	repInFlight map[string]chan struct{}
}

// New loads firewall state from path and starts a background expiry sweeper.
func New(path string) (*Firewall, error) {
	f := &Firewall{
		path:        path,
		nowFn:       func() int64 { return time.Now().Unix() },
		enabled:     true,
		def:         "allow",
		repCache:    make(map[string]repEntry),
		repInFlight: make(map[string]chan struct{}),
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
		f.rules = compileRules(s.Rules)
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
// port is the control port itself, so a rule can name it like any other.
func (f *Firewall) AllowControl(remoteAddr string, port int) (bool, string) {
	f.mu.RLock()
	on := f.enabled && f.controlPort
	f.mu.RUnlock()
	if !on {
		return true, "control port not protected"
	}
	return f.Allow(remoteAddr, port)
}

// Allow decides whether a user connection is permitted. port is the frps-side
// port the connection arrived on.
func (f *Firewall) Allow(remoteAddr string, port int) (bool, string) {
	f.mu.RLock()
	if !f.enabled {
		f.mu.RUnlock()
		return true, "firewall disabled"
	}
	now := f.nowFn()
	ip := parseAddr(remoteAddr)

	// 1) manual rules, in order
	for i := range f.rules {
		r := &f.rules[i]
		if r.ExpiresAt != 0 && r.ExpiresAt <= now {
			continue
		}
		if r.match(ip, port) {
			allow, reason := r.allow, r.reason
			f.mu.RUnlock()
			return allow, reason
		}
	}
	provider := f.provider
	client := f.client
	def := f.def
	selfCall := ip.IsValid() && f.isSelfCall(ip, port)
	f.mu.RUnlock()

	// 2) external reputation provider for unknown IPs. Our own call out to the
	// provider is exempt: it is the query, not something to run a query on.
	if (provider.Mode == "frpcontrol" || provider.Mode == "custom") && ip.IsValid() && !selfCall {
		if f.checkExternal(ip.String(), provider.effective(), client) {
			return false, "reputation"
		}
	}
	// 3) default policy
	if def == "allow" {
		return true, "default allow"
	}
	return false, "default deny"
}

// checkExternal returns whether ip is blocked according to the provider,
// caching per ip. On error it honors FailOpen (fail-closed = blocked).
//
// Lookups for the same IP are collapsed into one query: the cache is only
// written once an answer comes back, so without this a burst of connections
// from one unknown IP would all miss and each fire its own request - turning
// one visitor into a stampede against the provider.
func (f *Firewall) checkExternal(ipStr string, p ProviderConfig, client *http.Client) bool {
	for {
		now := f.nowFn()
		f.repMu.Lock()
		if e, ok := f.repCache[ipStr]; ok && e.exp > now {
			f.repMu.Unlock()
			return e.blocked
		}
		if ch, ok := f.repInFlight[ipStr]; ok {
			// Someone is already asking about this IP. Wait for their answer
			// instead of asking again, then re-read the cache.
			f.repMu.Unlock()
			<-ch
			continue
		}
		ch := make(chan struct{})
		f.repInFlight[ipStr] = ch
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
		delete(f.repInFlight, ipStr)
		f.repMu.Unlock()
		close(ch) // wakes the waiters, which now find the cache filled
		return blocked
	}
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
	return Snapshot{
		Enabled: f.enabled, ControlPort: f.controlPort, Default: f.def,
		Rules: plainRules(f.rules), Provider: f.provider,
	}
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
	f.rules = compileRules(rules)
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
	f.resolveSelfProviderLocked()
}

// resolveSelfProviderLocked works out whether the provider URL resolves back to
// this machine, and on which port.
//
// This is the shape that bites: the panel is published through a proxy on frps,
// so its URL is one of frps's own public ports. Every provider query then dials
// that port, which frps sees as a new user connection, which asks the provider
// again - each answer needing another answer first. Recorded here so Allow can
// leave our own calls alone.
//
// DNS and interface lookups happen here, on config change, never per connection.
func (f *Firewall) resolveSelfProviderLocked() {
	f.selfProviderPort = 0
	f.localIPs = netpkg.LocalAddrSet()

	p := f.provider.effective()
	if p.Mode == "off" || p.URL == "" {
		return
	}
	port := netpkg.PortIfLocal(strings.ReplaceAll(p.URL, "{ip}", "0.0.0.0"), f.localIPs)
	if port == 0 {
		return
	}
	f.selfProviderPort = port
	log.Warnf("firewall: provider URL %q resolves to this host on port %d; "+
		"connections from this host to that port skip the reputation check, "+
		"otherwise each check would trigger another one", p.URL, port)
}

// isSelfCall reports whether a connection is this frps dialing its own provider
// URL: from one of our addresses, to the port the provider lives on. A remote
// attacker cannot forge this - completing a TCP handshake from a spoofed local
// address needs to be on the path already, at which point the host is lost
// anyway.
func (f *Firewall) isSelfCall(ip netip.Addr, port int) bool {
	return f.selfProviderPort != 0 && port == f.selfProviderPort && f.localIPs[ip.String()]
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
	s := state{Enabled: &enabled, ControlPort: f.controlPort, Default: f.def, Rules: plainRules(f.rules), Provider: f.provider}
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

// parseAddr reads the source address of a connection. netip rather than net.IP:
// an Addr is a value, so this allocates nothing on a path that runs for every
// user connection and, for udp proxies, every packet.
func parseAddr(remoteAddr string) netip.Addr {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return netip.Addr{}
	}
	// An IPv4 client accepted on a dual-stack listener arrives as
	// ::ffff:a.b.c.d. Unmapping it is what lets an IPv4 rule match it at all.
	return addr.Unmap()
}

// parsePortRange reads one entry of a port spec: "6000" or "6000-6010".
func parsePortRange(part string) (lo, hi int, ok bool) {
	part = strings.TrimSpace(part)
	if part == "" {
		return 0, 0, false
	}
	before, after, isRange := strings.Cut(part, "-")
	lo, err := parsePort(before)
	if err != nil {
		return 0, 0, false
	}
	if !isRange {
		return lo, lo, true
	}
	hi, err = parsePort(after)
	if err != nil || hi < lo {
		return 0, 0, false
	}
	return lo, hi, true
}

func parsePort(s string) (int, error) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	if n < 0 || n > 65535 {
		return 0, fmt.Errorf("port %d out of range", n)
	}
	return n, nil
}

// ParsePortSpec validates a rule's port spec, so a bad one is rejected when the
// rule is saved rather than quietly failing to match later.
func ParsePortSpec(spec string) error {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" || strings.EqualFold(spec, "all") {
		return nil
	}
	for part := range strings.SplitSeq(spec, ",") {
		if _, _, ok := parsePortRange(part); !ok {
			return fmt.Errorf("invalid port %q: want a port, a lo-hi range, or all", strings.TrimSpace(part))
		}
	}
	return nil
}
