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

package firewall

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/fatedier/frp/pkg/util/log"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

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
	CacheTTLSec int `json:"cacheTTLSec,omitempty"` // how long an answer is current (default 300)
	TimeoutMs   int `json:"timeoutMs,omitempty"`   // request timeout (default 800)
	// FailOpen is what a proxy does with a source the provider has never
	// answered for while the provider cannot be reached: let it through (true)
	// or refuse it (false, the default). Nothing else turns on it. A source the
	// provider has answered for keeps that answer through an outage, and the
	// control port and the dashboard never refuse anyone for the provider being
	// down - see checkExternal.
	FailOpen    bool `json:"failOpen"`
	InsecureTLS bool `json:"insecureTLS,omitempty"` // skip TLS verify (self-signed)

	// Blocking makes a proxy connection from a source the provider has never
	// answered for wait for that first answer, instead of being judged by the
	// rules and the default policy while the lookup runs in the background.
	// Off by default, and worth understanding before turning on.
	//
	// The query is an http round trip - up to TimeoutMs - and on a udp proxy it
	// is spent in the read loop with nothing else being served, so one unknown
	// address delays everybody behind it. An attack made of unknown addresses,
	// which is what an attack is, turns the check into the outage. The control
	// port and the dashboard never wait, whatever this says.
	//
	// Asynchronous costs precision on a source's first contact only: whatever
	// arrives while the first lookup is out is decided without it, and every
	// connection after that has the answer. A refresh past CacheTTLSec runs in
	// the background with the previous answer still in force, in either mode.
	Blocking bool `json:"blocking,omitempty"`
}

// normalizeProvider fills in what a config may leave out, so two configs that
// mean the same thing also compare the same: an empty header map from the
// dashboard against a missing one from the file must not count as a change.
func normalizeProvider(p ProviderConfig) ProviderConfig {
	p.Mode = strings.ToLower(strings.TrimSpace(p.Mode))
	if p.Mode == "" {
		p.Mode = "off"
	}
	if len(p.Headers) == 0 {
		p.Headers = nil
	}
	return p
}

// active reports whether the provider is consulted at all.
func (p ProviderConfig) active() bool {
	return p.Mode == "frpcontrol" || p.Mode == "custom"
}

// query resolves the config into the request a lookup makes, or mode "off".
func (p ProviderConfig) query() ProviderConfig {
	if !p.active() {
		return ProviderConfig{Mode: "off"}
	}
	return p.effective()
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

const (
	// defaultCacheTTLSec is how long an answer counts as current when the
	// config does not say.
	defaultCacheTTLSec = 300

	// defaultTimeoutMs bounds one query when the config does not say.
	defaultTimeoutMs = 800

	// retryAfterFailureSec is how long a source waits after a failed lookup
	// before its next one, so a provider that is down is not asked again for
	// every connection.
	retryAfterFailureSec = 10

	// maxStaleSec is how long an answer keeps standing in after it stopped
	// being current. A source that keeps connecting refreshes its answer long
	// before this, so in practice it bounds how long an outage is ridden out on
	// old answers: a day, rather than holding on to a listing - or a clean bill
	// - long after the provider would have changed its mind.
	maxStaleSec = 24 * 60 * 60

	// maxReputationEntries bounds the cache. A flood from many addresses is
	// exactly the case that would otherwise grow it without limit.
	maxReputationEntries = 65536

	// maxConcurrentLookups bounds how many queries are out at once. Past it a
	// source goes unasked for now, rather than a flood from many addresses
	// becoming the same flood against the provider.
	maxConcurrentLookups = 64

	// healthLogEverySec spaces out the lines announcing that the provider went
	// away, so one that keeps flapping costs a line a minute rather than one
	// per lookup.
	healthLogEverySec = 60
)

// repEntry is what is known about one source from the provider.
type repEntry struct {
	// answered is set once the provider has answered for the source; blocked
	// and reason are its latest answer.
	answered bool
	blocked  bool
	reason   string
	// fresh is when that answer stops being current (unix sec). Past it the
	// answer is still used, and the next connection asks again.
	fresh int64
	// next is the earliest a new lookup may start: when the answer goes stale,
	// or retryAfterFailureSec after a lookup that failed.
	next int64
	// failed is set when the latest lookup got no answer.
	failed bool
}

// providerHealth is whether the provider has been answering, for the log and
// the dashboard.
type providerHealth struct {
	known   bool  // asked at least once since it was configured
	ok      bool  // whether the latest lookup got an answer
	since   int64 // when ok last changed, unix sec
	lastErr string
	// loggedDown is set when the current outage was announced, so that its end
	// is announced too - and only then. lastDownLog spaces the announcements.
	loggedDown  bool
	lastDownLog int64
}

// ProviderStatus is how the reputation provider is doing, for the dashboard.
type ProviderStatus struct {
	Mode string `json:"mode"`
	// State is "off" (not consulted), "unknown" (not asked yet), "ok" or
	// "unavailable".
	State string `json:"state"`
	// Since is when State last changed (unix sec), 0 if it never has.
	Since     int64  `json:"since,omitempty"`
	LastError string `json:"lastError,omitempty"`
	// Answered is how many sources have an answer on hand, and Listed how many
	// of those the provider has listed.
	Answered int `json:"answered"`
	Listed   int `json:"listed"`
}

// checkExternal reports whether the provider has ip listed, as far as the
// caller should act on it.
//
// Every source keeps the provider's latest answer. Past CacheTTLSec the next
// connection asks again in the background and is decided by the answer on
// hand, so a refresh never holds anybody up, and a provider that is slow or
// briefly down neither turns known addresses away nor waves listed ones in.
//
// Where there is no answer to go by, strict decides:
//
//   - strict, for proxies: the provider's word stands. A listed source stays
//     listed while the provider is down, and one it has never answered for is
//     refused or let through as FailOpen says. With Blocking on, a source it
//     has never answered for waits for that first answer.
//   - lenient, for the control port and the dashboard: the provider being
//     down refuses nobody, and nothing waits. A listing the provider can no
//     longer confirm is not acted on either. Both are frps's own way in - the
//     provider is often published through one of the clients the control port
//     serves, and the dashboard is where it would be fixed - so treating the
//     provider's absence as a refusal there turns any outage into one that
//     cannot end by itself.
//
// Lookups for one address are collapsed into a single query, and no more than
// maxConcurrentLookups are out at once: without both, a burst from one address
// or a flood from many would arrive at the provider as the same flood.
func (f *Firewall) checkExternal(ip string, p ProviderConfig, client *http.Client, strict bool) (bool, string) {
	now := f.nowFn()

	f.repMu.Lock()
	e := f.repCache[ip]
	ch, pending := f.repInFlight[ip]
	if !pending && now >= e.next {
		ch, pending = f.startLookupLocked(ip, p, client)
	}
	// Only a proxy waits, only when asked to, and only for a source with no
	// answer at all: a stale one stands while the new one is on its way.
	wait := strict && p.Blocking && !e.answered
	f.repMu.Unlock()

	if wait {
		if !pending {
			// Nothing to wait for: the last lookup failed and the next may not
			// start yet, or the provider already has as many as it is given at
			// once. Either way there is no answer, the same as an outage.
			reason := "provider busy"
			if e.failed {
				reason = "provider unavailable"
			}
			return unanswered(p, strict, reason)
		}
		<-ch
		f.repMu.Lock()
		e = f.repCache[ip]
		f.repMu.Unlock()
	}

	switch {
	case e.answered && (strict || !e.failed):
		// The provider's latest answer: current, or standing in while a newer
		// one is on its way - and, for a proxy, while the provider is down.
		return e.blocked, e.reason
	case e.failed || wait:
		return unanswered(p, strict, "provider unavailable")
	}
	// No answer yet; the lookup is running behind this connection.
	return false, ""
}

// unanswered is the verdict for a source the provider has said nothing usable
// about because it could not be asked. Only a proxy ever refuses for it.
func unanswered(p ProviderConfig, strict bool, reason string) (bool, string) {
	if strict && !p.FailOpen {
		return true, reason
	}
	return false, ""
}

// startLookupLocked sends the query for ip off in the background, unless
// maxConcurrentLookups are already out. Call with repMu held.
func (f *Firewall) startLookupLocked(ip string, p ProviderConfig, client *http.Client) (chan struct{}, bool) {
	select {
	case f.lookups <- struct{}{}:
	default:
		return nil, false
	}
	ch := make(chan struct{})
	f.repInFlight[ip] = ch
	go f.resolveExternal(ip, p, client, f.repGen, ch)
	return ch, true
}

// resolveExternal performs one lookup and records how it went, then releases
// whoever is waiting on ch.
func (f *Firewall) resolveExternal(ip string, p ProviderConfig, client *http.Client, gen uint64, ch chan struct{}) {
	blocked, reason, err := queryProvider(ip, p, client)

	now := f.nowFn()
	f.repMu.Lock()
	// A reset while this was out means the provider changed, and this answer
	// is from one nobody asks any more.
	current := gen == f.repGen
	if current {
		e := f.repCache[ip]
		if err != nil {
			e.failed = true
			e.next = now + retryAfterFailureSec
		} else {
			ttl := int64(p.CacheTTLSec)
			if ttl <= 0 {
				ttl = defaultCacheTTLSec
			}
			e = repEntry{answered: true, blocked: blocked, reason: reason, fresh: now + ttl, next: now + ttl}
		}
		f.storeLocked(ip, e)
		delete(f.repInFlight, ip)
	}
	f.repMu.Unlock()

	if current {
		f.noteProviderHealth(err, p.FailOpen)
	}
	close(ch) // waiters now find the outcome in the cache
	<-f.lookups
}

// storeLocked records e for ip, making room first when the cache is full. Call
// with repMu held.
func (f *Firewall) storeLocked(ip string, e repEntry) {
	if _, ok := f.repCache[ip]; !ok && len(f.repCache) >= maxReputationEntries {
		// Drop whichever entry the map hands out first. Map order is
		// randomized, so this is as good as picking at random, and it costs
		// nothing to choose.
		for k := range f.repCache {
			delete(f.repCache, k)
			break
		}
	}
	f.repCache[ip] = e
}

// resetReputation forgets every answer, for a provider that has just changed.
func (f *Firewall) resetReputation() {
	f.repMu.Lock()
	f.repCache = make(map[string]repEntry)
	f.repInFlight = make(map[string]chan struct{})
	f.repGen++
	f.repMu.Unlock()

	f.healthMu.Lock()
	f.health = providerHealth{lastDownLog: f.health.lastDownLog}
	f.healthMu.Unlock()
}

// pruneReputation drops answers too old to stand in for the provider any more,
// and failed lookups whose retry time has come.
func (f *Firewall) pruneReputation() {
	now := f.nowFn()

	f.repMu.Lock()
	defer f.repMu.Unlock()

	for ip, e := range f.repCache {
		if _, pending := f.repInFlight[ip]; pending {
			continue
		}
		if e.answered && now-e.fresh < maxStaleSec {
			continue
		}
		if !e.answered && now < e.next {
			continue
		}
		delete(f.repCache, ip)
	}
}

// noteProviderHealth records how a lookup went and says so in the log when the
// provider goes away or comes back - once per change rather than per lookup.
func (f *Firewall) noteProviderHealth(err error, failOpen bool) {
	now := f.nowFn()

	f.healthMu.Lock()
	defer f.healthMu.Unlock()

	h := &f.health
	if err == nil {
		if h.known && !h.ok && h.loggedDown {
			log.Infof("[FW] reputation provider is answering again after %s",
				(time.Duration(now-h.since) * time.Second).String())
		}
		if !h.known || !h.ok {
			h.known, h.ok, h.since, h.lastErr, h.loggedDown = true, true, now, "", false
		}
		return
	}

	h.lastErr = providerError(err)
	if h.known && !h.ok {
		return // the same outage
	}
	h.known, h.ok, h.since, h.loggedDown = true, false, now, false
	if now-h.lastDownLog < healthLogEverySec {
		return
	}
	h.loggedDown, h.lastDownLog = true, now
	unknown := "refuse"
	if failOpen {
		unknown = "let through"
	}
	log.Warnf("[FW] reputation provider unavailable: %s - the control port and the dashboard stay open; "+
		"proxies keep each address's last answer and %s addresses it has not answered for", h.lastErr, unknown)
}

// ProviderStatus reports whether the provider is answering and how much it has
// answered for.
func (f *Firewall) ProviderStatus() ProviderStatus {
	f.mu.RLock()
	st := ProviderStatus{Mode: f.provider.Mode, State: "off"}
	active := f.enabled && f.query.active()
	f.mu.RUnlock()
	if !active {
		return st
	}

	f.healthMu.Lock()
	h := f.health
	f.healthMu.Unlock()
	switch {
	case !h.known:
		st.State = "unknown"
	case h.ok:
		st.State = "ok"
	default:
		st.State = "unavailable"
		st.LastError = h.lastErr
	}
	st.Since = h.since

	f.repMu.Lock()
	for _, e := range f.repCache {
		if e.answered {
			st.Answered++
			if e.blocked {
				st.Listed++
			}
		}
	}
	f.repMu.Unlock()
	return st
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
		timeout = defaultTimeoutMs * time.Millisecond
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

// providerError describes a failed lookup for the log and the dashboard. The
// request URL is left out: a custom provider may carry its API key in it.
func providerError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "timed out"
	}
	return cleanText(err.Error(), 200)
}

// cleanReason makes a provider's answer safe to log. The string comes from
// another service over the network, so it is trimmed to one short line: a
// newline in it would otherwise let whoever runs that service write log entries
// of their own choosing into ours.
func cleanReason(s string) string {
	const maxReasonLen = 64
	return cleanText(s, maxReasonLen)
}

// cleanText cuts s to one line of at most maxLen bytes.
func cleanText(s string, maxLen int) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(s) {
		if b.Len() >= maxLen {
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

// buildClientLocked makes the http client lookups use, for the provider just
// configured. The previous client's idle connections are closed on the way:
// they lead to a provider nobody asks any more. Call with f.mu held.
func (f *Firewall) buildClientLocked() {
	if f.client != nil {
		f.client.CloseIdleConnections()
	}
	tr := &http.Transport{
		IdleConnTimeout: 90 * time.Second,
		// Lookups go to one host, often many at once; the default of two idle
		// connections would mean a fresh handshake for most of them.
		MaxIdleConnsPerHost: maxConcurrentLookups / 4,
	}
	if f.provider.InsecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 - opt-in for self-signed providers
	}
	f.client = &http.Client{Transport: tr}
}

// selfProvider works out whether the provider URL resolves back to this
// machine, and on which port, along with this host's own addresses.
//
// This is the shape that bites: the provider is published through a proxy on
// frps, so its URL is one of frps's own public ports. Every query then dials
// that port, which frps sees as a new user connection, which asks the provider
// again - each answer needing another answer first. Recorded so a decision can
// leave our own calls alone.
//
// DNS and interface lookups happen here, when the config changes, never per
// connection.
func selfProvider(q ProviderConfig) (int, map[string]bool) {
	local := netpkg.LocalAddrSet()
	if !q.active() || q.URL == "" {
		return 0, local
	}
	return netpkg.PortIfLocal(strings.ReplaceAll(q.URL, "{ip}", "0.0.0.0"), local), local
}

// logSelfProvider says once that the provider is reached through this host, so
// the exemption it earns is not a surprise.
func logSelfProvider(port int) {
	log.Infof("[FW] the provider URL resolves to this host on port %d: connections from this host to that "+
		"port skip the reputation check, or each check would trigger another one", port)
}

// isSelfCall reports whether a connection is this frps dialing its own provider
// URL: from one of our addresses, to the port the provider lives on. A remote
// attacker cannot forge this - completing a TCP handshake from a spoofed local
// address needs to be on the path already, at which point the host is lost
// anyway.
func (f *Firewall) isSelfCall(ip netip.Addr, port int) bool {
	return f.selfProviderPort != 0 && port == f.selfProviderPort && f.localIPs[ip.String()]
}
