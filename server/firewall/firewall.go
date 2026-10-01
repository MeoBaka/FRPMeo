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

// Package firewall is the access-control layer frps applies to the connections
// it accepts. With the firewall enabled, a connection is decided in this order:
//
//  1. Manual rules - ordered allow/deny by IP, CIDR or domain name and the
//     frps-side port the connection arrived on (first match wins).
//  2. Reputation provider (optional) - for a source no rule names, ask an
//     external blacklist whether it is listed. This can be an FRPControl
//     service (frps knows its API - you only supply URL + key) or a fully
//     custom API (configurable URL/method/headers + JSON path). Answers are
//     cached per address. frps never hosts the blacklist itself.
//  3. Default policy.
//
// User connections to proxies are always checked. The control port - with the
// kcp, quic and ssh gateway listeners that lead to the same place - and the
// dashboard are checked only when their own switch is on.
//
// It decides who may connect, not how often. Every check here runs after the
// kernel has accepted the connection, so floods are a job for whatever sits in
// front of frps: the host firewall or the hosting provider.
//
// IPv4, IPv6 and CIDR are supported.
package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/util/log"
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
	Port      string `json:"port"`
	Note      string `json:"note,omitempty"`
	ExpiresAt int64  `json:"expiresAt,omitempty"` // unix sec, 0 = permanent
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
	// reason is what a decision reports when this rule makes it, built here so
	// that deciding does not have to build a string.
	reason string
	// never marks a CIDR that does not parse. Such a rule matches nothing: a
	// rule that visibly does nothing beats a deny that quietly widens to
	// everything.
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
// dropped rather than widened, so a spec naming nothing valid matches nothing.
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
// from.
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

// state is the file format. A file written by a build that still had the
// anti-attacker may carry its sections; they are ignored, and dropped the next
// time the file is saved.
type state struct {
	Enabled          *bool          `json:"enabled,omitempty"` // nil = enabled
	ControlPort      bool           `json:"controlPort"`
	WebPort          bool           `json:"webPort"`
	Default          string         `json:"default"`
	Rules            []Rule         `json:"rules"`
	Provider         ProviderConfig `json:"provider"`
	DomainRefreshSec int            `json:"domainRefreshSec,omitempty"`
}

// Config is the whole of what the firewall is told, and the whole of what it
// reports back. One type for both directions rather than a list of arguments:
// three of the fields are booleans, and a caller that swapped two of them would
// turn a protected port into an open one without the compiler noticing.
type Config struct {
	Enabled bool `json:"enabled"`
	// ControlPort also covers the kcp, quic and ssh gateway listeners: all of
	// them are how a client reaches frps, and all of them lock every client
	// out if a deny default reaches them, so they answer to one switch.
	ControlPort bool `json:"controlPort"`
	// WebPort protects the dashboard. Off by default, and deliberately so: the
	// dashboard is where these rules are written, and a rule that shuts it can
	// only be undone by editing the state file on the host and restarting.
	WebPort  bool           `json:"webPort"`
	Default  string         `json:"default"`
	Rules    []Rule         `json:"rules"`
	Provider ProviderConfig `json:"provider"`
	// DomainRefreshSec is how often a rule that names a domain looks the name
	// up again. Zero uses defaultDomainRefreshSec.
	DomainRefreshSec int `json:"domainRefreshSec,omitempty"`
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
	// query is provider resolved into the request a lookup makes, or mode
	// "off". Built when the config changes, never per connection.
	query  ProviderConfig
	client *http.Client

	// selfProviderPort is set when the provider URL points back at this host,
	// e.g. the provider is only reachable through a proxy frps itself serves.
	// Asking the provider then means dialing our own public port, which is a
	// new user connection, which asks the provider again - so the provider
	// step is skipped for our own calls. 0 when the provider is elsewhere.
	// See selfProvider.
	selfProviderPort int
	// localIPs are this host's own addresses, resolved when the config is set
	// rather than per connection.
	localIPs map[string]bool

	// The reputation cache: what the provider last said about each source.
	// See checkExternal.
	repMu       sync.Mutex
	repCache    map[string]repEntry
	repInFlight map[string]chan struct{}
	// repGen counts cache resets, so a lookup started under one provider does
	// not land its answer in the cache kept for the next.
	repGen uint64
	// lookups bounds how many provider queries run at once.
	lookups chan struct{}

	healthMu sync.Mutex
	health   providerHealth

	// domains holds what the names used in rules currently resolve to, and
	// domainRefreshSec is how often it looks again.
	domains          *domainResolver
	domainRefreshSec int
	nowMsFn          func() int64

	// monitors aggregate what each surface decided, so a flood costs a line
	// every few seconds instead of one per connection.
	monitors map[Surface]*monitor
}

// New loads firewall state from path and starts the background work: expiring
// rules, refreshing the domains rules name, and reporting decisions.
func New(path string) (*Firewall, error) {
	f := &Firewall{
		path:        path,
		nowFn:       func() int64 { return time.Now().Unix() },
		nowMsFn:     func() int64 { return time.Now().UnixMilli() },
		enabled:     true,
		def:         "allow",
		repCache:    make(map[string]repEntry),
		repInFlight: make(map[string]chan struct{}),
		lookups:     make(chan struct{}, maxConcurrentLookups),
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
			return nil, fmt.Errorf("%s: %v", path, err)
		}
		f.enabled = s.Enabled == nil || *s.Enabled
		f.controlPort = s.ControlPort
		f.webPort = s.WebPort
		if f.def = normalizeDefault(s.Default); !validDefault(s.Default) {
			log.Warnf("[FW] %s: default policy %q is neither allow nor deny, using deny", path, s.Default)
		}
		f.rules = compileRules(s.Rules)
		f.provider = normalizeProvider(s.Provider)
		f.domainRefreshSec = s.DomainRefreshSec
	case os.IsNotExist(err):
		f.provider = normalizeProvider(ProviderConfig{})
	default:
		return nil, err
	}

	query := f.provider.query()
	selfPort, local := selfProvider(query)

	if selfPort != 0 {
		logSelfProvider(selfPort)
	}

	f.mu.Lock()
	f.query = query
	f.selfProviderPort, f.localIPs = selfPort, local
	f.buildClientLocked()
	f.pruneLocked()
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
		f.pruneReputation()
	}
}

// AllowControl decides whether a client may connect to the frps control port -
// or to the kcp, quic or ssh gateway listener - at all, checked on accept and
// so before login. port is the port it arrived on, so a rule can name it like
// any other.
//
// Opt-in via the controlPort toggle: protecting the control port with a
// deny-by-default policy locks out every client, so existing setups keep the
// old behavior until asked.
//
// Unlike a proxy, the control port never refuses anyone because the reputation
// provider cannot be reached, and never waits for it. The provider is often
// published through one of the very clients this port serves; refusing clients
// while it is down would keep it down for good, since the client carrying it
// could not log back in, and every other client would follow as its cached
// answer ran out. See checkExternal.
func (f *Firewall) AllowControl(remoteAddr string, port int) (bool, string) {
	f.mu.RLock()
	on := f.enabled && f.controlPort
	f.mu.RUnlock()
	if !on {
		return true, "control port not protected"
	}
	return f.decide(remoteAddr, port, false)
}

// AllowWeb decides whether a peer may reach the dashboard, checked on accept
// and so before the TLS handshake - a scanner speaking to the wrong protocol
// never gets far enough to be told so.
//
// Opt-in via the webPort toggle, and for a sharper reason than the control
// port's: the dashboard is where these rules are written. A rule that shuts it
// can only be undone by editing the state file on the host and restarting, so
// nobody is given that footgun without asking for it. For the same reason it
// treats the reputation provider like the control port does: the provider
// being down is when somebody needs to get in here.
func (f *Firewall) AllowWeb(remoteAddr string, port int) (bool, string) {
	f.mu.RLock()
	on := f.enabled && f.webPort
	f.mu.RUnlock()
	if !on {
		return true, "web port not protected"
	}
	return f.decide(remoteAddr, port, false)
}

// Allow decides whether a user connection to a proxy is permitted. port is the
// frps-side port the connection arrived on.
func (f *Firewall) Allow(remoteAddr string, port int) (bool, string) {
	return f.decide(remoteAddr, port, true)
}

// decide runs the rules, the provider and the default policy over one
// connection. strict says how to treat what the provider cannot tell us - see
// checkExternal.
//
// The reason is never empty, whichever way the decision goes: callers put it
// straight into a log line, and one that ends at "reason:" would say less than
// no line at all.
func (f *Firewall) decide(remoteAddr string, port int, strict bool) (bool, string) {
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
	query := f.query
	client := f.client
	def := f.def
	selfCall := ip.IsValid() && f.isSelfCall(ip, port)
	f.mu.RUnlock()

	// The provider can only refuse. Under a deny default everything it could
	// answer for is refused anyway, so asking would cost a lookup per unknown
	// address and change nothing but the wording of the log line.
	if def != "allow" {
		return false, "default deny"
	}

	// 2) external reputation provider for sources no rule names. Our own call
	// out to the provider is exempt: it is the query, not something to run a
	// query on.
	if query.active() && ip.IsValid() && !selfCall {
		if blocked, why := f.checkExternal(ip.String(), query, client, strict); blocked {
			if why != "" {
				return false, "reputation (" + why + ")"
			}
			return false, "reputation"
		}
	}

	// 3) default policy
	return true, "default allow"
}

// Snapshot returns the current state for the dashboard.
func (f *Firewall) Snapshot() Config {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return Config{
		Enabled: f.enabled, ControlPort: f.controlPort, WebPort: f.webPort,
		Default: f.def, Rules: plainRules(f.rules), Provider: f.provider,
		DomainRefreshSec: f.domainRefreshSec,
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
//
// The provider's answers are kept across a change that leaves the provider
// alone. Dropping them would put every source back to having no answer, and in
// the default asynchronous mode that waves each one through once more - a price
// nobody should pay for editing a rule.
func (f *Firewall) SetConfig(c Config) error {
	provider := normalizeProvider(c.Provider)
	query := provider.query()
	// DNS and interface lookups, so outside the lock: decisions wait on it.
	selfPort, local := selfProvider(query)

	f.mu.Lock()
	defer f.mu.Unlock()
	f.enabled = c.Enabled
	f.controlPort = c.ControlPort
	f.webPort = c.WebPort
	f.def = normalizeDefault(c.Default)
	f.rules = compileRules(c.Rules)
	if selfPort != 0 && selfPort != f.selfProviderPort {
		logSelfProvider(selfPort)
	}
	f.selfProviderPort, f.localIPs = selfPort, local
	if !reflect.DeepEqual(f.provider, provider) {
		f.provider = provider
		f.query = query
		f.buildClientLocked()
		f.resetReputation()
	}
	f.domainRefreshSec = c.DomainRefreshSec
	f.domains.setHosts(ruleHosts(f.rules), f.domainRefreshSec)
	return f.saveLocked()
}

// --- internals (call with f.mu held) ---

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
		DomainRefreshSec: f.domainRefreshSec,
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

// validDefault reports whether s names a default policy at all.
func validDefault(s string) bool {
	s = strings.TrimSpace(s)
	return s == "" || strings.EqualFold(s, "allow") || strings.EqualFold(s, "deny")
}

// normalizeDefault reads a default policy. Blank is allow, the long-standing
// default; anything that is neither word is deny, so a typo in a hand-edited
// file errs towards keeping strangers out rather than letting everyone in.
func normalizeDefault(s string) string {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "allow") {
		return "allow"
	}
	return "deny"
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

// ValidateDefault rejects a default policy that is neither allow nor deny, so
// the dashboard is told rather than having it quietly read as deny.
func ValidateDefault(s string) error {
	if !validDefault(s) {
		return fmt.Errorf("default policy must be allow or deny, not %q", s)
	}
	return nil
}
