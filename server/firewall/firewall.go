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
	"sort"
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
	// CIDR is what the rule matches a source against: "1.2.3.0/24", "::1",
	// "1.2.3.4", a domain name, or "" / "*" for any.
	//
	// A domain is resolved in the background and looked up again on an
	// interval, so a rule can name a connection whose address moves - an office
	// or a home line on dynamic DNS - and keep meaning the same thing. It works
	// the same for either action: allow follows the name in, deny follows it
	// out.
	CIDR string `json:"cidr"`
	// Port is a Windows-firewall style spec: "6000", "6000-6010",
	// "80,443,7000-7010", or "" / "*" / "all" for any port.
	Port string `json:"port"`
	// Trusted exempts a matching source from the rate limits, the bans and the
	// reputation provider, not only from the rules. Meaningless on a deny rule.
	//
	// Off by default, and deliberately a separate switch rather than something
	// every allow rule does: an allow rule is usually "this may through", not
	// "stop protecting this". Turn it on for the addresses you cannot afford to
	// have locked out by a counter - your own office, a monitoring probe, the
	// one client whose reconnect storm looks exactly like an attack - and keep
	// the list short, because it does turn every other layer off for them.
	Trusted   bool   `json:"trusted,omitempty"`
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
	// ReasonPath optionally points at a string the provider returns to say why
	// an IP is blocked, e.g. results.0.reason. It only reaches the log, so a
	// provider that does not answer with one costs nothing: the rejection is
	// still reported, just as a bare "reputation".
	ReasonPath string `json:"reasonPath,omitempty"`

	// common
	CacheTTLSec int  `json:"cacheTTLSec,omitempty"` // per-ip cache (default 300)
	TimeoutMs   int  `json:"timeoutMs,omitempty"`   // request timeout (default 800)
	FailOpen    bool `json:"failOpen"`              // on error: allow (true) or block (false)
	InsecureTLS bool `json:"insecureTLS,omitempty"` // skip TLS verify (self-signed)

	// Blocking makes a source wait for the provider's first answer about it
	// instead of being judged by the rules and the default policy while the
	// lookup runs in the background. Off by default, and worth understanding
	// before turning on.
	//
	// The query is an http round trip - up to TimeoutMs - and the paths that
	// ask are the ones accepting traffic. On the dashboard listener and the udp
	// read loop that time is spent with nothing else being served, so one
	// unknown address delays everybody. An attack made of unknown addresses,
	// which is what an attack is, turns the check into the outage.
	//
	// Asynchronous costs precision on exactly one connection per source: the
	// first is decided without the provider, and every one after it has the
	// answer. Against a scanner that connects once that changes nothing, since
	// the verdict would have arrived too late to matter either way. Against a
	// repeat visitor - which is what the logs are full of - it costs one
	// connection and keeps the server responsive.
	Blocking bool `json:"blocking,omitempty"`
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
		// Read alongside the verdict when the service returns it. Absent, the
		// rejection reads as a plain "reputation" - no configuration needed
		// either way.
		ReasonPath:  "results.0.reason",
		CacheTTLSec: p.CacheTTLSec,
		TimeoutMs:   p.TimeoutMs,
		FailOpen:    p.FailOpen,
		InsecureTLS: p.InsecureTLS,
		Blocking:    p.Blocking,
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
	// host is set when the target is a domain rather than an address, in which
	// case prefix is unused and matching asks the resolver instead.
	host    string
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

// ruleReason names a rule in the line that reports a rejection. Rules created
// through the API always carry an id, but a hand-written state file need not,
// and a log entry trailing off after "reason: rule " names nothing at all - so
// a rule without one is identified by where it sits in the list.
func ruleReason(id string, index int) string {
	if id = strings.TrimSpace(id); id != "" {
		return "rule " + id
	}
	return "rule #" + strconv.Itoa(index+1)
}

func compileRules(rules []Rule) []compiledRule {
	if len(rules) == 0 {
		return nil
	}
	out := make([]compiledRule, 0, len(rules))
	for i, r := range rules {
		out = append(out, compileRule(r, i))
	}
	return out
}

func compileRule(r Rule, index int) compiledRule {
	c := compiledRule{
		Rule:   r,
		allow:  strings.EqualFold(strings.TrimSpace(r.Action), "allow"),
		reason: ruleReason(r.ID, index),
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
			// Not an address, so it may be a name. A name that is not plausible
			// either leaves host empty and never set, which is the same answer
			// a malformed CIDR gets: a rule that visibly does nothing beats one
			// that quietly widens.
			if c.host = normalizeDomain(cidr); c.host == "" {
				c.never = true
			}
			break
		}
		addr = addr.Unmap()
		c.prefix = netip.PrefixFrom(addr, addr.BitLen())
	}

	c.ports, c.anyPort = compilePorts(r.Port)
	return c
}

// ruleHosts is every domain the rules name, for the resolver to keep current.
func ruleHosts(rules []compiledRule) []string {
	out := make([]string, 0, len(rules))
	for i := range rules {
		if h := rules[i].host; h != "" {
			out = append(out, h)
		}
	}
	return out
}

// compilePorts reads a port spec into the ranges it names. A malformed entry is
// dropped rather than widened, so a spec naming nothing valid matches nothing -
// see matchPort's old contract, which this keeps.
func compilePorts(spec string) (ranges []portRange, anyPort bool) {
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

func (c *compiledRule) match(ip netip.Addr, port int, res *domainResolver) bool {
	if !c.matchSource(ip, res) {
		return false
	}
	return c.anyPort || matchRanges(c.ports, port)
}

// matchSource is the half of match that looks only at where the connection came
// from. Split out because trust is a statement about a source: the counting
// layers it exempts are per-source, and have no port to check against.
func (c *compiledRule) matchSource(ip netip.Addr, res *domainResolver) bool {
	switch {
	case c.never:
		return false
	case c.anyCIDR:
		return true
	case !ip.IsValid():
		return false
	case c.host != "":
		return res.has(c.host, ip)
	default:
		return c.prefix.Contains(ip)
	}
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
	Enabled          *bool              `json:"enabled,omitempty"` // nil = enabled
	ControlPort      bool               `json:"controlPort"`
	WebPort          bool               `json:"webPort"`
	Default          string             `json:"default"`
	Rules            []Rule             `json:"rules"`
	Provider         ProviderConfig     `json:"provider"`
	AntiAttacker     AntiAttackerConfig `json:"antiAttacker"`
	DomainRefreshSec int                `json:"domainRefreshSec,omitempty"`
}

// Config is the whole of what the firewall is told, and the whole of what it
// reports back. One type for both directions rather than a list of arguments:
// three of the fields are booleans, and a caller that swapped two of them would
// turn a protected port into an open one without the compiler noticing.
type Config struct {
	Enabled bool `json:"enabled"`
	// ControlPort also covers the ssh tunnel gateway: both are how a client
	// reaches frps, both lock every client out if a deny default reaches them,
	// so both answer to one switch.
	ControlPort bool `json:"controlPort"`
	// WebPort protects the dashboard. Off by default, and deliberately so: the
	// dashboard is where these rules are written, and a rule that shuts it can
	// only be undone by editing the state file on the host and restarting.
	WebPort  bool           `json:"webPort"`
	Default  string         `json:"default"`
	Rules    []Rule         `json:"rules"`
	Provider ProviderConfig `json:"provider"`
	// AntiAttacker rate-limits sources that the rules and the provider already
	// let through. Off by default; see AntiAttackerConfig.
	AntiAttacker AntiAttackerConfig `json:"antiAttacker"`
	// DomainRefreshSec is how often a rule that names a domain looks the name
	// up again. Zero uses defaultDomainRefreshSec.
	DomainRefreshSec int `json:"domainRefreshSec,omitempty"`
}

type repEntry struct {
	blocked bool
	reason  string
	exp     int64
}

// Firewall holds live state and persists it to a JSON file.
type Firewall struct {
	mu    sync.RWMutex
	path  string
	nowFn func() int64

	enabled     bool
	controlPort bool
	webPort     bool
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

	// aa and its limiters are the rate-limiting half.
	aa          AntiAttackerConfig
	tcpLimiter  *limiter
	httpLimiter *limiter
	udpLimiter  *udpLimiter
	// ctlLimiter is kept apart from tcpLimiter on purpose. One frpc client is
	// both a control connection and a stream of work connections from the same
	// address, and it may also be reaching proxies from there; sharing a
	// counter would let one of those starve the other.
	ctlLimiter *limiter
	// webLimiter and sshLimiter are likewise their own: the dashboard, the ssh
	// gateway and the control port are three different doors, and someone
	// hammering one must not use up another's budget.
	webLimiter *limiter
	sshLimiter *limiter

	// The pieces that are not about counting attempts: attack state, the
	// exemption store, the strike counters and the concurrency ledger.
	attack    *attackState
	trust     *trustStore
	strikes   *strikeStore
	conc      *concurrency
	startedAt int64 // ms, for the grace period
	nowMsFn   func() int64

	// domains holds what the names used in rules currently resolve to, and
	// domainRefreshSec is how often it looks again.
	domains          *domainResolver
	domainRefreshSec int

	// monitors aggregate what each surface decided, so a flood costs a line
	// every few seconds instead of one per connection.
	monitors map[Surface]*monitor
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
		tcpLimiter:  newLimiter(nil),
		httpLimiter: newLimiter(nil),
		udpLimiter:  newUDPLimiter(nil),
		ctlLimiter:  newLimiter(nil),
		webLimiter:  newLimiter(nil),
		sshLimiter:  newLimiter(nil),
		attack:      newAttackState(nil),
		trust:       newTrustStore(nil),
		strikes:     newStrikeStore(nil),
		conc:        newConcurrency(),
		nowMsFn:     func() int64 { return time.Now().UnixMilli() },
		startedAt:   time.Now().UnixMilli(),
		monitors:    make(map[Surface]*monitor, len(surfaces)),
	}
	f.domains = newDomainResolver(f.nowMsFn)
	for _, s := range surfaces {
		f.monitors[s] = newMonitor(string(s))
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
		f.webPort = s.WebPort
		f.def = orDefault(strings.ToLower(s.Default), "allow")
		f.rules = compileRules(s.Rules)
		f.provider = s.Provider
		f.aa = s.AntiAttacker
		f.domainRefreshSec = s.DomainRefreshSec
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
	f.applyAntiAttackerLocked(f.aa)
	f.domains.setHosts(ruleHosts(f.rules), f.domainRefreshSec)
	_ = f.saveLocked()
	f.mu.Unlock()

	// Resolved once before serving rather than on the first tick. A rule naming
	// a domain decides nothing until the name has an address behind it, and the
	// first client to arrive is exactly who an allow rule was written for.
	f.domains.refresh(context.Background())

	go f.sweep()
	go f.refreshDomains()
	go f.reportSurfaces()
	return f, nil
}

// refreshDomains keeps the names used in rules current. It wakes often and does
// nothing most of the time - what is due is decided per name against the
// configured interval, so a config change takes effect without restarting this.
func (f *Firewall) refreshDomains() {
	t := time.NewTicker(domainTickSec * time.Second)
	defer t.Stop()
	for range t.C {
		f.domains.refresh(context.Background())
	}
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

// AllowWeb decides whether a peer may reach the dashboard, checked on accept
// and so before the TLS handshake - a scanner speaking to the wrong protocol
// never gets far enough to be told so.
//
// Opt-in via the webPort toggle, and for a sharper reason than the control
// port's: the dashboard is where these rules are written. A rule that shuts it
// can only be undone by editing the state file on the host and restarting, so
// nobody is given that footgun without asking for it.
func (f *Firewall) AllowWeb(remoteAddr string, port int) (bool, string) {
	f.mu.RLock()
	on := f.enabled && f.webPort
	f.mu.RUnlock()
	if !on {
		return true, "web port not protected"
	}
	return f.Allow(remoteAddr, port)
}

// Allow decides whether a user connection is permitted. port is the frps-side
// port the connection arrived on.
//
// The reason is never empty, whichever way the decision goes: callers put it
// straight into a log line, and one that ends at "reason:" would say less than
// no line at all.
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
		if r.match(ip, port, f.domains) {
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
		if blocked, why := f.checkExternal(ip.String(), provider.effective(), client); blocked {
			if why != "" {
				return false, "reputation (" + why + ")"
			}
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
// With Blocking off - the default - a source the cache has no answer for is
// reported as not blocked and the lookup is started in the background, so the
// caller is never held up by an http round trip. The answer is there for that
// source's next connection. See ProviderConfig.Blocking.
//
// Lookups for the same IP are collapsed into one query either way: the cache is
// only written once an answer comes back, so without this a burst of
// connections from one unknown IP would all miss and each fire its own request,
// turning one visitor into a stampede against the provider.
func (f *Firewall) checkExternal(ipStr string, p ProviderConfig, client *http.Client) (bool, string) {
	for {
		now := f.nowFn()
		f.repMu.Lock()
		if e, ok := f.repCache[ipStr]; ok && e.exp > now {
			f.repMu.Unlock()
			return e.blocked, e.reason
		}
		if ch, ok := f.repInFlight[ipStr]; ok {
			if !p.Blocking {
				// Somebody is already asking; this caller does not wait for it.
				f.repMu.Unlock()
				return false, ""
			}
			// Wait for their answer instead of asking again, then re-read the
			// cache.
			f.repMu.Unlock()
			<-ch
			continue
		}
		ch := make(chan struct{})
		f.repInFlight[ipStr] = ch
		f.repMu.Unlock()

		if !p.Blocking {
			go f.resolveExternal(ipStr, p, client, ch)
			return false, ""
		}
		f.resolveExternal(ipStr, p, client, ch)

		f.repMu.Lock()
		e, ok := f.repCache[ipStr]
		f.repMu.Unlock()
		if !ok {
			return false, ""
		}
		return e.blocked, e.reason
	}
}

// resolveExternal performs one lookup and writes the verdict to the cache,
// releasing whoever is waiting on ch. Runs on its own goroutine when the
// provider is asynchronous, inline when it is not.
func (f *Firewall) resolveExternal(ipStr string, p ProviderConfig, client *http.Client, ch chan struct{}) {
	blocked, reason, err := queryProvider(ipStr, p, client)
	ttl := int64(p.CacheTTLSec)
	if ttl <= 0 {
		ttl = 300
	}
	if err != nil {
		blocked = !p.FailOpen // fail-closed by default
		reason = "provider unavailable"
		ttl = 10 // don't hammer a failing provider
	}
	f.repMu.Lock()
	f.repCache[ipStr] = repEntry{blocked: blocked, reason: reason, exp: f.nowFn() + ttl}
	delete(f.repInFlight, ipStr)
	f.repMu.Unlock()
	close(ch) // wakes any waiters, which now find the cache filled
}

// queryProvider asks the provider about one IP and reports its verdict, plus
// whatever reason it gave for it.
func queryProvider(ipStr string, p ProviderConfig, client *http.Client) (bool, string, error) {
	if p.URL == "" || p.BlockedPath == "" {
		return false, "", errors.New("provider url/blockedPath not set")
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
		return false, "", err
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
		return false, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("provider status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return false, "", err
	}
	var data any
	if err := json.Unmarshal(raw, &data); err != nil {
		return false, "", err
	}
	blocked := truthy(extractPath(data, p.BlockedPath, ipStr))
	reason := ""
	if blocked && p.ReasonPath != "" {
		if s, ok := extractPath(data, p.ReasonPath, ipStr).(string); ok {
			reason = cleanReason(s)
		}
	}
	return blocked, reason, nil
}

// cleanReason makes a provider's answer safe to log. The string comes from
// another service over the network, so it is trimmed to one short line: a
// newline in it would otherwise let whoever runs that service write log entries
// of their own choosing into ours.
func cleanReason(s string) string {
	const maxReasonLen = 64

	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if b.Len() >= maxReasonLen {
			break
		}
		// Anything below space - newline, carriage return, the terminal escapes
		// that color our own output - becomes a space.
		if r < ' ' || r == 0x7f {
			r = ' '
		}
		b.WriteRune(r)
	}
	return strings.TrimSpace(b.String())
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
func (f *Firewall) Snapshot() Config {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return Config{
		Enabled: f.enabled, ControlPort: f.controlPort, WebPort: f.webPort,
		Default: f.def, Rules: plainRules(f.rules), Provider: f.provider,
		AntiAttacker: f.aa, DomainRefreshSec: f.domainRefreshSec,
	}
}

// DomainStatus reports what each domain named by a rule currently resolves to.
//
// A name that stopped resolving is still matching its old addresses and nothing
// else, which is a thing an operator has to be able to see - an allow rule that
// quietly stopped covering somebody and a deny rule that quietly stopped
// blocking them are the same failure.
func (f *Firewall) DomainStatus() []DomainStatus {
	return f.domains.status()
}

// SetConfig replaces the whole configuration.
func (f *Firewall) SetConfig(c Config) error {
	def := strings.ToLower(c.Default)
	if def != "allow" && def != "deny" {
		def = "allow"
	}
	provider := c.Provider
	if provider.Mode == "" {
		provider.Mode = "off"
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = c.Enabled
	f.controlPort = c.ControlPort
	f.webPort = c.WebPort
	f.def = def
	f.rules = compileRules(c.Rules)
	f.provider = provider
	f.buildClientLocked()
	f.applyAntiAttackerLocked(c.AntiAttacker)
	f.domainRefreshSec = c.DomainRefreshSec
	f.domains.setHosts(ruleHosts(f.rules), f.domainRefreshSec)
	f.repMu.Lock()
	f.repCache = make(map[string]repEntry)
	f.repMu.Unlock()
	return f.saveLocked()
}

// applyAntiAttackerLocked stores a normalized config. Counters are dropped
// whenever the settings change: they were
// accumulated against different thresholds, and keeping them could hold someone
// in a ban that the new settings would never have handed out.
func (f *Firewall) applyAntiAttackerLocked(c AntiAttackerConfig) {
	f.aa = c.normalize()
	f.tcpLimiter.reset()
	f.httpLimiter.reset()
	f.udpLimiter.reset()
	f.ctlLimiter.reset()
	f.webLimiter.reset()
	f.sshLimiter.reset()
	f.attack.reset()
	f.conc.reset()
	// Trust and strikes survive a config change on purpose. Both are records of
	// what a source actually did, not counters accumulated against a threshold
	// that just moved - throwing them away would re-measure people who had
	// already earned their exemption, and forgive peers caught red-handed.
}

// inGrace reports whether frps is still inside the window after startup where
// no check applies. Called with no lock held; startedAt never changes.
func (f *Firewall) inGrace(grace int) bool {
	return grace > 0 && f.nowMsFn()-f.startedAt < int64(grace)*1000
}

// exempt gathers the three ways an admission decision can be skipped entirely,
// so every Admit* answers them the same way and in the same order.
//
// Grace first: a server that has just started has no business banning anybody,
// least of all the clients reconnecting to it. Then trust, which is a source
// that already proved itself. Only then is a strike ban consulted - it comes
// last of the three because unlike the others it is a refusal, not a pass.
func (f *Firewall) exempt(key string, c AntiAttackerConfig) (skip bool, refuse bool) {
	if f.inGrace(c.GraceSeconds) {
		return true, false
	}
	// A rule marked trusted covers the counting layers too, not only the rules.
	// An exemption that stopped at the rules would still let a reconnect storm
	// from the one client you cannot lock out get it banned.
	if f.trustedSource(parseAddr(key)) {
		return true, false
	}
	if f.trust.trusted(key, c.Trust) {
		return true, false
	}
	if f.strikes.banned(key, c.Strikes) {
		return false, true
	}
	return false, false
}

// trustedSource reports whether an allow rule marked trusted names ip.
//
// The port is not consulted, unlike everywhere else rules are matched. What
// this exempts is the counting layers, and those count per source rather than
// per destination: a client is one budget however many of your ports it reaches
// for. So a trusted rule is read as a statement about who is connecting, and
// the port it names still narrows the allow half of the rule as usual.
func (f *Firewall) trustedSource(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	f.mu.RLock()
	defer f.mu.RUnlock()

	if !f.enabled {
		return false
	}
	now := f.nowFn()
	for i := range f.rules {
		r := &f.rules[i]
		if !r.allow || !r.Trusted {
			continue
		}
		if r.ExpiresAt != 0 && r.ExpiresAt <= now {
			continue
		}
		if r.matchSource(ip, f.domains) {
			return true
		}
	}
	return false
}

// banning reports whether a rate-limit violation may escalate to a ban.
//
// Only while frps is actually under attack. A quiet server has no business
// banning anyone: the throttle has already turned the attempt away, and the
// step from "you are asking too often" to "you are locked out for a minute" is
// the one that hurts a real client who happened to have a bad minute. Under
// attack that judgement flips - a source still overflowing its window is the
// thing the ban exists for.
//
// With the attack detector switched off there is no "under attack" to consult,
// so violations escalate as they always did. Turning the detector off must not
// quietly disable banning along with it.
func (f *Firewall) banning(c AntiAttackerConfig) bool {
	if !c.Attack.Enabled {
		return true
	}
	return f.attack.isUnder()
}

var verdictStruck = Verdict{Reason: "struck (not a client)"}

// IsUnderAttack reports whether the connection rate has crossed the threshold
// that makes the blunter measures worth their cost.
func (f *Firewall) IsUnderAttack() bool {
	f.mu.RLock()
	on := f.enabled && f.aa.Enabled && f.aa.Attack.Enabled
	f.mu.RUnlock()
	return on && f.attack.isUnder()
}

// HandshakeTimeout returns how long to wait for a peer to say something,
// shortening the caller's default while under attack.
//
// A connection that opens and stays silent costs a socket for the whole
// timeout, so this is the cheapest answer to a slow flood there is. It is also
// the one that would hurt honest clients on bad links if it were permanent,
// which is why it only applies while the attack state is on.
func (f *Firewall) HandshakeTimeout(def time.Duration) time.Duration {
	f.mu.RLock()
	ms := f.aa.Attack.InitialTimeoutMs
	on := f.enabled && f.aa.Enabled && f.aa.Attack.Enabled
	f.mu.RUnlock()
	if !on || ms <= 0 || !f.attack.isUnder() {
		return def
	}
	if d := time.Duration(ms) * time.Millisecond; d < def {
		return d
	}
	return def
}

// HandshakeByteLimit is how much a peer may send before it has finished
// identifying itself, or 0 for no limit.
//
// Not gated on the attack state, unlike the timeout it sits beside: the ceiling
// is far enough above anything a real client sends that leaving it armed costs
// nothing, and a peer spending our memory is worth cutting off whether or not
// the connection rate has crossed a line.
func (f *Firewall) HandshakeByteLimit() int {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if !f.enabled || !f.aa.Enabled || !f.aa.Attack.Enabled {
		return 0
	}
	return f.aa.Attack.InitialBufferLimitBytes
}

// ReportProtocolFailure records that a peer failed to speak frp's protocol - a
// non-TLS connection to a TLS-only port, a login that did not verify.
//
// Worth more than any amount of counting: an frpc having a bad day still speaks
// frp. Something that does not is not a client, and after a few of these it is
// banned outright.
func (f *Firewall) ReportProtocolFailure(remoteAddr string) {
	f.mu.RLock()
	c := f.aa.Strikes
	on := f.enabled && f.aa.Enabled && c.Enabled && !f.inGrace(f.aa.GraceSeconds)
	f.mu.RUnlock()
	if !on {
		return
	}
	f.strikes.add(clientKey(remoteAddr, "", nil), strikeProtocol, c)
}

// NoteConnectionClosed is called when a user connection finishes, with how long
// it lasted and how many bytes crossed it. It feeds the two things that can
// only be known afterwards: whether the source earned trust, and whether it is
// scanning.
//
// One hook for both because they read the same evidence and disagree about it.
// A connection that lasted and carried traffic is somebody using the tunnel; a
// string of connections that carried nothing is somebody looking to see what is
// listening.
func (f *Firewall) NoteConnectionClosed(remoteAddr string, dur time.Duration, bytes int64) {
	f.mu.RLock()
	trust, strikes := f.aa.Trust, f.aa.Strikes
	on := f.enabled && f.aa.Enabled && !f.inGrace(f.aa.GraceSeconds)
	f.mu.RUnlock()
	if !on {
		return
	}
	key := clientKey(remoteAddr, "", nil)

	if trust.Enabled && dur >= time.Duration(trust.AfterMs)*time.Millisecond && bytes >= int64(trust.MinBytes) {
		f.trust.grant(key, trust)
		return
	}
	if strikes.Enabled && bytes < int64(strikes.EmptyBytes) {
		f.strikes.add(key, strikeEmpty, strikes)
	}
}

// AcquireConn takes a concurrency slot for the source, reporting false when it
// already holds as many connections as the profile allows. The returned release
// must be called when the connection ends; it is a no-op when the cap is off.
func (f *Firewall) AcquireConn(remoteAddr string) (ok bool, release func()) {
	f.mu.RLock()
	limit := f.aa.TCP.MaxConcurrent
	on := f.enabled && f.aa.Enabled && f.aa.TCP.Enabled && limit > 0 && !f.inGrace(f.aa.GraceSeconds)
	f.mu.RUnlock()
	if !on {
		return true, func() {}
	}
	key := clientKey(remoteAddr, "", nil)
	if !f.conc.acquire(key, limit) {
		return false, func() {}
	}
	return true, func() { f.conc.release(key) }
}

// AdmitTCP rate-limits one accepted user connection, after the rules and the
// provider have allowed it. user and proxyName say which proxy it arrived on,
// so a config scoped to named proxies can skip the rest.
//
// Callers should close a refused connection with RST rather than a graceful
// close - see netpkg.CloseWithReset. A refusal that leaves a socket in
// TIME_WAIT for two minutes is a poor answer to a flood.
func (f *Firewall) AdmitTCP(remoteAddr string) Verdict {
	f.mu.RLock()
	c := f.aa
	on := f.enabled && c.Enabled
	f.mu.RUnlock()
	if !on {
		return verdictAllow
	}
	// Counted even when this proxy is out of scope and even during grace: the
	// attack state is a reading of the whole server's load, and one taken only
	// from the parts still being policed would be the wrong number.
	f.attack.note(c.Attack)

	if !c.TCP.Enabled {
		return verdictAllow
	}
	key := clientKey(remoteAddr, "", nil)
	if skip, refuse := f.exempt(key, c); skip {
		return verdictAllow
	} else if refuse {
		return verdictStruck
	}
	return f.tcpLimiter.admitBoth(key, c.TCP, f.banning(c))
}

// AdmitHTTP rate-limits one request served by the vhost reverse proxy. xff is
// the raw X-Forwarded-For header, which is only believed when the peer is
// covered by an allow rule marked trusted.
//
// Per request rather than per connection because the reverse proxy pools work
// connections by route: checking at connection setup would wave through every
// request that landed on an already-open one.
func (f *Firewall) AdmitHTTP(remoteAddr, xff string) Verdict {
	f.mu.RLock()
	c := f.aa
	on := f.enabled && c.Enabled && c.HTTP.Enabled
	f.mu.RUnlock()
	if !on {
		return verdictAllow
	}
	key := clientKey(remoteAddr, xff, f.trustedSource)
	if skip, refuse := f.exempt(key, c); skip {
		return verdictAllow
	} else if refuse {
		return verdictStruck
	}
	return f.httpLimiter.admitBoth(key, c.HTTP.RateProfile, f.banning(c))
}

// AdmitControl rate-limits one connection to the frps control port, after
// AllowControl has allowed it.
//
// Armed by its own AntiAttacker.Control.Protect switch.
//
// Note what a refusal means here, which is not what it means for a user
// connection: the peer is an frpc client, and turning it away keeps its tunnels
// down until it gets back in. The default limits are correspondingly loose.
func (f *Firewall) AdmitControl(remoteAddr string) Verdict {
	f.mu.RLock()
	c := f.aa
	on := f.enabled && c.Enabled && c.Control.Protect
	f.mu.RUnlock()
	if !on {
		return verdictAllow
	}
	f.attack.note(c.Attack)

	key := clientKey(remoteAddr, "", nil)
	if skip, refuse := f.exempt(key, c); skip {
		return verdictAllow
	} else if refuse {
		return verdictStruck
	}
	return f.ctlLimiter.admitBoth(key, c.Control.RateProfile, f.banning(c))
}

// AdmitWeb rate-limits one connection to the dashboard port, after AllowWeb has
// allowed it. Armed by AntiAttacker.Web.Protect.
//
// Worth knowing before turning it on: this page is what edits these settings.
// The limit is sized so a page load cannot trip it, but somebody who sets it
// very low can lock themselves out until frps_firewall.json is edited by hand.
func (f *Firewall) AdmitWeb(remoteAddr string) Verdict {
	f.mu.RLock()
	c := f.aa
	on := f.enabled && c.Enabled && c.Web.Protect
	f.mu.RUnlock()
	if !on {
		return verdictAllow
	}
	f.attack.note(c.Attack)

	key := clientKey(remoteAddr, "", nil)
	if skip, refuse := f.exempt(key, c); skip {
		return verdictAllow
	} else if refuse {
		return verdictStruck
	}
	return f.webLimiter.admitBoth(key, c.Web.RateProfile, f.banning(c))
}

// AdmitSSH rate-limits one connection to the ssh tunnel gateway port, after
// AllowControl has allowed it. Armed by AntiAttacker.SSH.Protect.
func (f *Firewall) AdmitSSH(remoteAddr string) Verdict {
	f.mu.RLock()
	c := f.aa
	on := f.enabled && c.Enabled && c.SSH.Protect
	f.mu.RUnlock()
	if !on {
		return verdictAllow
	}
	f.attack.note(c.Attack)

	key := clientKey(remoteAddr, "", nil)
	if skip, refuse := f.exempt(key, c); skip {
		return verdictAllow
	} else if refuse {
		return verdictStruck
	}
	return f.sshLimiter.admitBoth(key, c.SSH.RateProfile, f.banning(c))
}

// AdmitUDP rate-limits one UDP packet of size bytes, for the udp and pe proxies
// and the udp half of tcp+udp. It reports whether to forward the packet; a
// refusal is a silent drop, since UDP has no way to say no.
//
// Returns a bool rather than a Verdict: there is nowhere for a reason or a
// retry hint to go, and this runs per packet.
func (f *Firewall) AdmitUDP(remoteAddr string, size int) bool {
	f.mu.RLock()
	p := f.aa.UDP
	on := f.enabled && f.aa.Enabled && p.Enabled
	f.mu.RUnlock()
	if !on {
		return true
	}
	return f.udpLimiter.admit(clientKey(remoteAddr, "", nil), size, p)
}

// AntiAttackerStatus reports what the rate limiting is doing right now, as
// opposed to what it is configured to do.
//
// This exists because everything above is deliberately quiet: a rate-limit
// refusal writes no log line, since a flood being turned away must not become a
// flood of writes. That leaves no way to tell a working configuration from one
// that is off, and no way to find out who is being turned away - which is what
// somebody looking at this page actually wants to know.
func (f *Firewall) AntiAttackerStatus() Status {
	f.mu.RLock()
	c := f.aa
	on := f.enabled && c.Enabled
	f.mu.RUnlock()

	st := Status{Tracked: map[string]int{}}
	if !on {
		st.Bans = []BanEntry{}
		return st
	}
	now := f.nowMsFn()
	st.UnderAttack = c.Attack.Enabled && f.attack.isUnder()
	st.InGrace = f.inGrace(c.GraceSeconds)
	st.Trusted = f.trust.size()
	st.OpenConns = f.conc.size()
	st.Tracked = map[string]int{
		"tcp":     f.tcpLimiter.size(),
		"http":    f.httpLimiter.size(),
		"udp":     f.udpLimiter.size(),
		"control": f.ctlLimiter.size(),
		"web":     f.webLimiter.size(),
		"ssh":     f.sshLimiter.size(),
		"strikes": f.strikes.size(),
	}

	bans := make([]BanEntry, 0, 16)
	bans = append(bans, f.tcpLimiter.bans("tcp", now)...)
	bans = append(bans, f.httpLimiter.bans("http", now)...)
	bans = append(bans, f.ctlLimiter.bans("control", now)...)
	bans = append(bans, f.webLimiter.bans("web", now)...)
	bans = append(bans, f.sshLimiter.bans("ssh", now)...)
	bans = append(bans, f.strikes.bans(now)...)
	sort.Slice(bans, func(i, j int) bool { return bans[i].SecondsLeft > bans[j].SecondsLeft })
	st.Bans = bans
	return st
}

// ClearAntiAttackerBans lifts every ban and forgets every strike, for the
// operator who has just fixed whatever was tripping it and does not want to
// wait the ban out. Trust is kept: it was earned, and nothing here revokes it.
func (f *Firewall) ClearAntiAttackerBans() {
	f.tcpLimiter.reset()
	f.httpLimiter.reset()
	f.udpLimiter.reset()
	f.ctlLimiter.reset()
	f.webLimiter.reset()
	f.sshLimiter.reset()
	f.strikes.reset()
	f.conc.reset()
}

// RetryAfterSeconds is what an HTTP 429 should advertise for this verdict: the
// configured override when set, otherwise however long the source actually has
// to wait, rounded up so a client that obeys it does not come back too early.
func (f *Firewall) RetryAfterSeconds(v Verdict) int {
	f.mu.RLock()
	override := f.aa.HTTP.RetryAfterSec
	f.mu.RUnlock()
	if override > 0 {
		return override
	}
	return max(int((v.RetryAfter+time.Second-1)/time.Second), 1)
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
	s := state{
		Enabled: &enabled, ControlPort: f.controlPort, WebPort: f.webPort,
		Default: f.def, Rules: plainRules(f.rules), Provider: f.provider,
		AntiAttacker: f.aa, DomainRefreshSec: f.domainRefreshSec,
	}
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
