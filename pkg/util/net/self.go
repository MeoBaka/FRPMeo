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

package net

import (
	"net"
	"net/url"
	"strconv"
	"strings"
)

// This file exists for one shape of misconfiguration, which frps can be talked
// into by an ordinary-looking setup: an endpoint frps calls out to - a firewall
// reputation provider, a server plugin - that is only reachable through a proxy
// frps itself serves.
//
// The call then dials one of frps's own public ports, so frps sees a new user
// connection, so it makes the call again. Nothing about the endpoint looks
// wrong; the loop lives in the topology. Recognizing it needs two facts: which
// addresses are ours, and which port the endpoint sits on.

// LocalAddrSet returns every address this host answers on, keyed for lookup.
//
// Resolve this once and keep it: it walks the interfaces, which is far too much
// work to repeat per connection.
//
// Note it cannot see a public address that is NAT'ed to this host (a cloud
// elastic IP, a forwarded container port). An endpoint reached through such an
// address still loops, and still has to be broken with an explicit rule.
func LocalAddrSet() map[string]bool {
	set := map[string]bool{}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return set
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			set[ipnet.IP.String()] = true
		}
	}
	return set
}

// PortIfLocal returns the port of rawEndpoint when its host is one of ours, and
// 0 otherwise. rawEndpoint may be a URL ("https://host:7002/api") or a bare
// address ("host:7002"). Its host is resolved, so this does DNS - call it when
// configuration changes, never per connection.
func PortIfLocal(rawEndpoint string, local map[string]bool) int {
	host, port := splitEndpoint(rawEndpoint)
	if host == "" || port == 0 {
		return 0
	}
	addrs, err := net.LookupHost(host)
	if err != nil {
		return 0
	}
	for _, a := range addrs {
		if local[a] {
			return port
		}
	}
	return 0
}

// IsLocalAddr reports whether remoteAddr ("host:port" or a bare host) comes
// from this machine.
func IsLocalAddr(remoteAddr string, local map[string]bool) bool {
	host := remoteAddr
	if h, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = h
	}
	return local[host]
}

func splitEndpoint(raw string) (host string, port int) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", 0
	}
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return "", 0
	}
	if s := u.Port(); s != "" {
		p, err := strconv.Atoi(s)
		if err != nil {
			return "", 0
		}
		return u.Hostname(), p
	}
	switch u.Scheme {
	case "https":
		return u.Hostname(), 443
	case "http":
		return u.Hostname(), 80
	}
	return "", 0
}
