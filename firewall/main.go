// frp-firewall: a standalone access-control service for frps.
//
// frps calls it on every new user connection via the NewUserConn HTTP plugin
// hook; this service checks IP/CIDR + proxy + user rules and tells frps to
// allow or reject the connection - before it reaches the tunneled service.
//
// One instance can serve many frps: each frps points its [[httpPlugins]] at a
// distinct path (/plugin/<id>), and rules are stored per id under the data dir.
package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

type config struct {
	listen      string
	dataDir     string
	apiToken    string // if set, /api requires "Authorization: Bearer <token>"
	pluginToken string // optional shared secret in the path (use only over https)
	allowIPs    string // comma-separated IP/CIDR of frps hosts allowed to call /plugin
	corsOrig    string
}

func loadConfig() config {
	return config{
		listen:      envOr("FW_LISTEN", ":9001"),
		dataDir:     envOr("FW_DATA", "./data"),
		apiToken:    os.Getenv("FW_API_TOKEN"),
		pluginToken: os.Getenv("FW_PLUGIN_TOKEN"),
		allowIPs:    os.Getenv("FW_ALLOW_IPS"),
		corsOrig:    envOr("FW_CORS_ORIGIN", "*"),
	}
}

func tokenEq(a, b string) bool {
	return len(a) == len(b) && subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// --- frp plugin wire format (standalone copy, no frp import) ---

type pluginRequest struct {
	Version string          `json:"version"`
	Op      string          `json:"op"`
	Content json.RawMessage `json:"content"`
}

type pluginResponse struct {
	Reject       bool   `json:"reject"`
	RejectReason string `json:"reject_reason,omitempty"`
	Unchange     bool   `json:"unchange"`
}

type newUserConnContent struct {
	User struct {
		User  string            `json:"user"`
		Metas map[string]string `json:"metas"`
		RunID string            `json:"run_id"`
	} `json:"user"`
	ProxyName  string `json:"proxy_name"`
	ProxyType  string `json:"proxy_type"`
	RemoteAddr string `json:"remote_addr"`
}

type server struct {
	cfg       config
	store     *Store
	allowNets []*net.IPNet
}

func parseNets(csv string) []*net.IPNet {
	var nets []*net.IPNet
	for _, part := range strings.Split(csv, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if !strings.Contains(part, "/") {
			if strings.Contains(part, ":") {
				part += "/128"
			} else {
				part += "/32"
			}
		}
		if _, n, err := net.ParseCIDR(part); err == nil {
			nets = append(nets, n)
		} else {
			log.Printf("warning: ignoring invalid FW_ALLOW_IPS entry %q", part)
		}
	}
	return nets
}

func main() {
	cfg := loadConfig()
	store, err := NewStore(cfg.dataDir)
	if err != nil {
		log.Fatalf("init store: %v", err)
	}
	s := &server{cfg: cfg, store: store, allowNets: parseNets(cfg.allowIPs)}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /plugin/{id}", s.handlePlugin)
	mux.HandleFunc("POST /plugin/{token}/{id}", s.handlePluginTok)
	mux.HandleFunc("GET /api/servers", s.withAPI(s.handleListServers))
	mux.HandleFunc("GET /api/rules/{id}", s.withAPI(s.handleGetRules))
	mux.HandleFunc("PUT /api/rules/{id}", s.withAPI(s.handlePutRules))
	mux.HandleFunc("POST /api/decide/{id}", s.withAPI(s.handleTestDecide))
	mux.HandleFunc("OPTIONS /api/", s.handlePreflight)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte("ok"))
	})

	log.Printf("frp-firewall listening on %s (data=%s, apiAuth=%v, pluginToken=%v, allowIPs=%d)",
		cfg.listen, cfg.dataDir, cfg.apiToken != "", cfg.pluginToken != "", len(s.allowNets))
	srv := &http.Server{Addr: cfg.listen, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// handlePlugin serves /plugin/{id}; allowed only when no plugin token is set.
func (s *server) handlePlugin(w http.ResponseWriter, r *http.Request) {
	if s.cfg.pluginToken != "" {
		writeJSON(w, pluginResponse{Reject: true, RejectReason: "firewall: plugin token required"})
		return
	}
	s.decidePlugin(w, r, r.PathValue("id"))
}

// handlePluginTok serves /plugin/{token}/{id} and verifies the shared token, so
// only frps that know it can query this (possibly shared) firewall service and
// others cannot fetch/abuse it.
func (s *server) handlePluginTok(w http.ResponseWriter, r *http.Request) {
	if s.cfg.pluginToken == "" || !tokenEq(r.PathValue("token"), s.cfg.pluginToken) {
		writeJSON(w, pluginResponse{Reject: true, RejectReason: "firewall: invalid plugin token"})
		return
	}
	s.decidePlugin(w, r, r.PathValue("id"))
}

// sourceAllowed reports whether the plugin caller (frps) is permitted by the
// FW_ALLOW_IPS list. Empty list = allow any (rely on network isolation).
func (s *server) sourceAllowed(r *http.Request) bool {
	if len(s.allowNets) == 0 {
		return true
	}
	ip := parseIP(r.RemoteAddr)
	if ip == nil {
		return false
	}
	for _, n := range s.allowNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// decidePlugin runs the NewUserConn allow/deny decision for a server id.
func (s *server) decidePlugin(w http.ResponseWriter, r *http.Request, id string) {
	if !s.sourceAllowed(r) {
		log.Printf("[%s] plugin call from %s rejected: caller IP not allowed", id, r.RemoteAddr)
		writeJSON(w, pluginResponse{Reject: true, RejectReason: "firewall: caller IP not allowed"})
		return
	}
	if !safeID(id) {
		writeJSON(w, pluginResponse{Reject: true, RejectReason: "invalid firewall id"})
		return
	}
	var req pluginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, pluginResponse{Reject: true, RejectReason: "bad plugin request"})
		return
	}
	// Only NewUserConn is inspected; pass everything else through untouched.
	if req.Op != "NewUserConn" {
		writeJSON(w, pluginResponse{Unchange: true})
		return
	}
	var c newUserConnContent
	if err := json.Unmarshal(req.Content, &c); err != nil {
		writeJSON(w, pluginResponse{Reject: true, RejectReason: "bad content"})
		return
	}
	ip := parseIP(c.RemoteAddr)
	allow, reason := s.store.Decide(id, ip, c.ProxyName, c.User.User)
	log.Printf("[%s] %s user=%q proxy=%q -> %s (%s)", id, c.RemoteAddr, c.User.User, c.ProxyName, verdict(allow), reason)
	if allow {
		writeJSON(w, pluginResponse{Unchange: true})
		return
	}
	writeJSON(w, pluginResponse{Reject: true, RejectReason: "blocked by firewall: " + reason})
}

// --- REST API (consumed by the web/frps Firewall tab) ---

func (s *server) handleListServers(w http.ResponseWriter, _ *http.Request) {
	ids, err := s.store.List()
	if err != nil {
		httpError(w, 500, err.Error())
		return
	}
	type item struct {
		ID      string `json:"id"`
		Default string `json:"default"`
		Rules   int    `json:"rules"`
	}
	out := []item{}
	for _, id := range ids {
		rs, _ := s.store.Load(id)
		out = append(out, item{ID: id, Default: rs.Default, Rules: len(rs.Rules)})
	}
	writeJSON(w, out)
}

func (s *server) handleGetRules(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !safeID(id) {
		httpError(w, 400, "invalid id")
		return
	}
	rs, err := s.store.Load(id)
	if err != nil {
		httpError(w, 500, err.Error())
		return
	}
	writeJSON(w, rs)
}

func (s *server) handlePutRules(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !safeID(id) {
		httpError(w, 400, "invalid id")
		return
	}
	var rs RuleSet
	if err := json.NewDecoder(r.Body).Decode(&rs); err != nil {
		httpError(w, 400, "bad json")
		return
	}
	if rs.Default != "allow" && rs.Default != "deny" {
		rs.Default = "allow"
	}
	for i := range rs.Rules {
		a := strings.ToLower(rs.Rules[i].Action)
		if a != "allow" && a != "deny" {
			httpError(w, 400, "rule action must be allow or deny")
			return
		}
		rs.Rules[i].Action = a
		if rs.Rules[i].ID == "" {
			rs.Rules[i].ID = randID()
		}
	}
	if err := s.store.Save(id, &rs); err != nil {
		httpError(w, 500, err.Error())
		return
	}
	writeJSON(w, map[string]any{"ok": true, "id": id, "rules": len(rs.Rules)})
}

func (s *server) handleTestDecide(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !safeID(id) {
		httpError(w, 400, "invalid id")
		return
	}
	var body struct {
		IP    string `json:"ip"`
		Proxy string `json:"proxy"`
		User  string `json:"user"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, 400, "bad json")
		return
	}
	allow, reason := s.store.Decide(id, net.ParseIP(strings.TrimSpace(body.IP)), body.Proxy, body.User)
	writeJSON(w, map[string]any{"allow": allow, "reason": reason})
}

func (s *server) handlePreflight(w http.ResponseWriter, r *http.Request) {
	s.setCORS(w)
	w.WriteHeader(http.StatusNoContent)
}

// withAPI wraps API handlers with CORS + optional bearer-token auth.
func (s *server) withAPI(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.setCORS(w)
		if s.cfg.apiToken != "" {
			got := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
			if got != s.cfg.apiToken {
				httpError(w, 401, "unauthorized")
				return
			}
		}
		h(w, r)
	}
}

func (s *server) setCORS(w http.ResponseWriter) {
	w.Header().Set("Access-Control-Allow-Origin", s.cfg.corsOrig)
	w.Header().Set("Access-Control-Allow-Methods", "GET, PUT, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
}

// --- helpers ---

func parseIP(remoteAddr string) net.IP {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	return net.ParseIP(strings.TrimSpace(host))
}

func verdict(allow bool) string {
	if allow {
		return "ALLOW"
	}
	return "REJECT"
}

func randID() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpError(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
