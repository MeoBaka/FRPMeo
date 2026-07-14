package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// Rule is a single firewall rule. Empty CIDR/Proxy/User means "match any".
// The first rule that matches (top to bottom) decides the verdict.
type Rule struct {
	ID     string `json:"id"`
	Action string `json:"action"` // "allow" | "deny"
	CIDR   string `json:"cidr"`   // "1.2.3.0/24", "1.2.3.4", "" or "*" = any
	Proxy  string `json:"proxy"`  // glob e.g. "rdp-*", "" or "*" = any
	User   string `json:"user"`   // glob, "" or "*" = any
	Note   string `json:"note"`
}

// RuleSet is one server's (or the global) rule list plus its fallback policy.
type RuleSet struct {
	Default string `json:"default"` // "allow" | "deny" (fallback when nothing matches)
	Rules   []Rule `json:"rules"`
}

// matchRules returns the action of the first matching rule.
func matchRules(rules []Rule, ip net.IP, proxy, user string) (action, ruleID string, ok bool) {
	for _, r := range rules {
		if !matchCIDR(r.CIDR, ip) {
			continue
		}
		if !matchGlob(r.Proxy, proxy) {
			continue
		}
		if !matchGlob(r.User, user) {
			continue
		}
		return strings.ToLower(r.Action), r.ID, true
	}
	return "", "", false
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
	// leading part must be a prefix
	if parts[0] != "" && !strings.HasPrefix(sl, parts[0]) {
		return false
	}
	// trailing part must be a suffix
	if last := parts[len(parts)-1]; last != "" && !strings.HasSuffix(sl, last) {
		return false
	}
	// middle parts must appear in order
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

// Store persists one RuleSet per id as data/<id>.json. id "global" applies to all.
type Store struct {
	dir string
	mu  sync.RWMutex
}

func NewStore(dir string) (*Store, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	return &Store{dir: dir}, nil
}

func safeID(id string) bool {
	if id == "" || len(id) > 64 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func (s *Store) path(id string) string { return filepath.Join(s.dir, id+".json") }

func (s *Store) Load(id string) (*RuleSet, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	b, err := os.ReadFile(s.path(id))
	if os.IsNotExist(err) {
		return &RuleSet{Default: "allow", Rules: []Rule{}}, nil
	}
	if err != nil {
		return nil, err
	}
	var rs RuleSet
	if err := json.Unmarshal(b, &rs); err != nil {
		return nil, err
	}
	if rs.Rules == nil {
		rs.Rules = []Rule{}
	}
	if rs.Default == "" {
		rs.Default = "allow"
	}
	return &rs, nil
}

func (s *Store) Save(id string, rs *RuleSet) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if rs.Rules == nil {
		rs.Rules = []Rule{}
	}
	b, err := json.MarshalIndent(rs, "", "  ")
	if err != nil {
		return err
	}
	tmp := s.path(id) + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, s.path(id))
}

// List returns all server ids that have a rule file (including "global").
func (s *Store) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var ids []string
	for _, e := range entries {
		name := e.Name()
		if strings.HasSuffix(name, ".json") {
			ids = append(ids, strings.TrimSuffix(name, ".json"))
		}
	}
	sort.Strings(ids)
	return ids, nil
}

// Decide evaluates global rules first, then the server's rules, then the
// fallback default (server default wins, else global default, else "allow").
func (s *Store) Decide(id string, ip net.IP, proxy, user string) (allow bool, reason string) {
	global, _ := s.Load("global")
	server, _ := s.Load(id)

	if a, rid, ok := matchRules(global.Rules, ip, proxy, user); ok {
		return a == "allow", "global rule " + rid
	}
	if a, rid, ok := matchRules(server.Rules, ip, proxy, user); ok {
		return a == "allow", id + " rule " + rid
	}
	def := server.Default
	if def == "" {
		def = global.Default
	}
	if def == "" {
		def = "allow"
	}
	return strings.ToLower(def) == "allow", "default " + def
}
