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

package secure

import (
	"net"
	"net/http"
	"strings"
	"sync"
)

// KnockRegistry sends unlock requests that reach frps' http port, for a domain
// no http proxy serves, to the secure https proxy that owns the domain.
type KnockRegistry struct {
	mu       sync.RWMutex
	byDomain map[string]*Gate
}

func NewKnockRegistry() *KnockRegistry {
	return &KnockRegistry{byDomain: make(map[string]*Gate)}
}

// Register makes g answer unlock requests for domain.
func (r *KnockRegistry) Register(domain string, g *Gate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byDomain[strings.ToLower(domain)] = g
}

// Unregister undoes Register, unless another gate has taken the domain since.
func (r *KnockRegistry) Unregister(domain string, g *Gate) {
	r.mu.Lock()
	defer r.mu.Unlock()
	key := strings.ToLower(domain)
	if r.byDomain[key] == g {
		delete(r.byDomain, key)
	}
}

// ServeNoRoute answers req when its host belongs to a secure https proxy, and
// reports whether it did. It is installed as the http reverse proxy's handler
// for requests that match no http route.
func (r *KnockRegistry) ServeNoRoute(rw http.ResponseWriter, req *http.Request) bool {
	if req.Method == http.MethodConnect {
		return false
	}
	g := r.lookup(req.Host)
	if g == nil {
		return false
	}
	g.ServeKnock(rw, req)
	return true
}

func (r *KnockRegistry) lookup(host string) *Gate {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)

	r.mu.RLock()
	defer r.mu.RUnlock()

	if g := r.byDomain[host]; g != nil {
		return g
	}
	// Wildcard domains, the way vhost routes them: *.example.com covers
	// a.example.com and a.b.example.com.
	for {
		_, parent, ok := strings.Cut(host, ".")
		if !ok || parent == "" {
			return nil
		}
		if g := r.byDomain["*."+parent]; g != nil {
			return g
		}
		host = parent
	}
}
