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

// secureFormFields are the names frps' own sign-in form sends the title and
// the key under. A title of either name would read as one of them.
var secureFormFields = []string{v1.SecureFormTitleField, v1.SecureFormKeyField}

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
	for i, cr := range c.AllCredentials() {
		field := "secure"
		if i > 0 {
			field = fmt.Sprintf("secure.credentials[%d]", i-1)
		}
		if err := validateSecureCredential(field, cr, c); err != nil {
			return err
		}
	}
	for _, m := range c.Methods {
		if !slices.Contains(v1.SecureMethods, m) {
			return fmt.Errorf("secure.methods: unknown method %q, valid are %s", m, strings.Join(v1.SecureMethods, ", "))
		}
		// An empty list quietly means "the defaults that apply"; naming one
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

// validateSecureCredential checks one title/key pair. field names it in the
// error: "secure" for the first, "secure.credentials[i]" for the rest.
func validateSecureCredential(field string, cr v1.SecureCredential, c *v1.SecureConfig) error {
	if !secureTitlePattern.MatchString(cr.Title) {
		return fmt.Errorf("%s.title: 1-64 letters, digits, '-' or '_' (for example \"auth\" or \"dangnhap\")", field)
	}
	if slices.Contains(secureReservedTitles, strings.ToLower(cr.Title)) {
		return fmt.Errorf("%s.title: %q is a header HTTP itself relies on, choose another name", field, cr.Title)
	}
	if slices.Contains(secureFormFields, strings.ToLower(cr.Title)) {
		return fmt.Errorf("%s.title: %q is a field of frps' own sign-in form, choose another name", field, cr.Title)
	}
	// basic and bearer read the Authorization header, so a title of that name
	// would have the header method read the same header as well.
	if (c.HasMethod(v1.SecureMethodBasic) || c.HasMethod(v1.SecureMethodBearer)) &&
		strings.EqualFold(cr.Title, "authorization") {
		return fmt.Errorf("%s.title: \"authorization\" is the header basic and bearer use, choose another name", field)
	}
	if len(cr.Key) < minSecureKeyLen || len(cr.Key) > maxSecureKeyLen {
		return fmt.Errorf("%s.key: must be %d-%d characters", field, minSecureKeyLen, maxSecureKeyLen)
	}
	if strings.TrimSpace(cr.Key) != cr.Key || strings.ContainsFunc(cr.Key, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("%s.key: no leading or trailing spaces and no control characters", field)
	}
	return nil
}

// validateSecureHTTPAuth refuses basic and bearer on an http proxy that has
// frp's own basic authentication. Both read the one Authorization header a
// request carries, so whichever looked second would see the other's
// credentials and turn the visitor away.
func validateSecureHTTPAuth(c *v1.HTTPProxyConfig) error {
	s := &c.Secure
	if !s.Enable || (c.HTTPUser == "" && c.HTTPPassword == "" && c.RouteByHTTPUser == "") {
		return nil
	}
	for _, m := range []string{v1.SecureMethodBasic, v1.SecureMethodBearer} {
		if s.HasMethod(m) {
			return fmt.Errorf("secure.methods: %q cannot be used together with httpUser, httpPassword or routeByHTTPUser, "+
				"which read the same Authorization header", m)
		}
	}
	return nil
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
