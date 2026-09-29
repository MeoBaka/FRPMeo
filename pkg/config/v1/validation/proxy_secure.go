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

package validation

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strings"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

// secureTitlePattern keeps the title usable everywhere it travels: as an HTTP
// header name, a query parameter, a form field and a line prefix.
var secureTitlePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Header names HTTP itself depends on. frps strips the title header before
// forwarding a request, so one of these would take the request apart.
var secureReservedTitles = []string{"host", "cookie", "connection", "content-length", "content-type", "transfer-encoding"}

const (
	minSecureKeyLen = 6
	maxSecureKeyLen = 256
)

// The visitor types already make every caller prove a secretKey through an
// frpc visitor, and are never reached by a browser or a bare client.
var secureUnsupportedTypes = []string{
	string(v1.ProxyTypeSTCP),
	string(v1.ProxyTypeSUDP),
	string(v1.ProxyTypeXTCP),
	string(v1.ProxyTypeXUDP),
	string(v1.ProxyTypeSTCPSUDP),
	string(v1.ProxyTypeXTCPXUDP),
}

func validateSecureConfig(base *v1.ProxyBaseConfig) error {
	c := &base.Secure
	if !c.Enable {
		return nil
	}
	if slices.Contains(secureUnsupportedTypes, base.Type) {
		return fmt.Errorf("secure: not supported for %s proxies, which already require secretKey", base.Type)
	}
	// Each proxy of a group keeps its own record of unlocked addresses, so a
	// visitor unlocked by one member would be refused by the next.
	if base.LoadBalancer.Group != "" {
		return errors.New("secure: not supported together with loadBalancer.group")
	}
	if !secureTitlePattern.MatchString(c.Title) {
		return errors.New("secure.title: 1-64 letters, digits, '-' or '_' (for example \"auth\" or \"dangnhap\")")
	}
	if slices.Contains(secureReservedTitles, strings.ToLower(c.Title)) {
		return fmt.Errorf("secure.title: %q is a header HTTP itself relies on, choose another name", c.Title)
	}
	if len(c.Key) < minSecureKeyLen || len(c.Key) > maxSecureKeyLen {
		return fmt.Errorf("secure.key: must be %d-%d characters", minSecureKeyLen, maxSecureKeyLen)
	}
	if strings.TrimSpace(c.Key) != c.Key || strings.ContainsFunc(c.Key, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return errors.New("secure.key: no leading or trailing spaces and no control characters")
	}
	for _, m := range c.Methods {
		if !slices.Contains(v1.SecureMethods, m) {
			return fmt.Errorf("secure.methods: unknown method %q, valid are %s", m, strings.Join(v1.SecureMethods, ", "))
		}
		// An empty list quietly means "every method that applies"; naming one
		// that cannot work is a mistake worth reporting back to frpc.
		if m == v1.SecureMethodLine && !v1.SecureLineApplies(base.Type) {
			return fmt.Errorf("secure.methods: %q is not supported for %s proxies, which have no first line to carry a key", m, base.Type)
		}
	}
	if c.UnlockSeconds < 0 {
		return errors.New("secure.unlockSeconds: must not be negative")
	}
	if err := validateSecureIPList("secure.allowIPs", c.AllowIPs); err != nil {
		return err
	}
	return validateSecureIPList("secure.trustedIPs", c.TrustedIPs)
}

func validateSecureIPList(field string, entries []string) error {
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if _, err := netip.ParsePrefix(e); err == nil {
			continue
		}
		if _, err := netip.ParseAddr(e); err != nil {
			return fmt.Errorf("%s: %q is not an IP or CIDR", field, e)
		}
	}
	return nil
}
