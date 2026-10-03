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
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
)

func secureBase(proxyType string, edit func(*v1.ProxyBaseConfig)) *v1.ProxyBaseConfig {
	base := &v1.ProxyBaseConfig{
		Name: "p",
		Type: proxyType,
		Secure: v1.SecureConfig{
			Enable: true,
			Title:  "dangnhap",
			Key:    "secret123",
		},
	}
	if edit != nil {
		edit(base)
	}
	return base
}

func TestValidateSecureConfig(t *testing.T) {
	cases := []struct {
		name    string
		base    *v1.ProxyBaseConfig
		wantErr string
	}{
		{name: "defaults", base: secureBase("tcp", nil)},
		{name: "off ignores everything else", base: secureBase("stcp", func(b *v1.ProxyBaseConfig) {
			b.Secure = v1.SecureConfig{Title: "bad title"}
		})},
		{name: "every public type", base: secureBase("pe", nil)},
		{name: "visitor types already have a secret", base: secureBase("stcp", nil), wantErr: "secretKey"},
		{name: "no load balancing group", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.LoadBalancer.Group = "g"
		}), wantErr: "loadBalancer.group"},
		{name: "title must be a token", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Title = "dang nhap"
		}), wantErr: "secure.title"},
		{name: "title must not be an HTTP header", base: secureBase("http", func(b *v1.ProxyBaseConfig) {
			b.Secure.Title = "Cookie"
		}), wantErr: "secure.title"},
		{name: "key too short", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Key = "abc"
		}), wantErr: "secure.key"},
		{name: "key with padding", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Key = " secret123"
		}), wantErr: "secure.key"},
		{name: "key with a line break", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Key = "secret\n123"
		}), wantErr: "secure.key"},
		{name: "unknown method", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Methods = []string{"smoke-signal"}
		}), wantErr: "unknown method"},
		{name: "line on tcp", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Methods = []string{"line"}
		})},
		{name: "line on http is reported to frpc", base: secureBase("http", func(b *v1.ProxyBaseConfig) {
			b.Secure.Methods = []string{"link", "line"}
		}), wantErr: "not supported for http"},
		{name: "line on mc is reported to frpc", base: secureBase("mc", func(b *v1.ProxyBaseConfig) {
			b.Secure.Methods = []string{"line"}
		}), wantErr: "not supported for mc"},
		{name: "every method on http means the ones that apply", base: secureBase("http", nil)},
		{name: "each newer method by name", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Methods = []string{"basic", "header", "form", "json", "bearer"}
		})},
		{name: "basic alone on http", base: secureBase("http", func(b *v1.ProxyBaseConfig) {
			b.Secure.Methods = []string{"basic"}
		})},
		{name: "basic cannot share the Authorization header with a title of that name", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Title = "Authorization"
			b.Secure.Methods = []string{"basic", "header"}
		}), wantErr: "secure.title"},
		{name: "nor can bearer", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Title = "authorization"
			b.Secure.Methods = []string{"bearer"}
		}), wantErr: "secure.title"},
		{name: "a title of that name is fine without them", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Title = "authorization"
			b.Secure.Methods = []string{"header"}
		})},
		{name: "more logins", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Credentials = []v1.SecureCredential{{Title: "anna", Key: "anna-key-1"}, {Title: "bob", Key: "bob-key-1"}}
		})},
		{name: "every login follows the title rules", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Credentials = []v1.SecureCredential{{Title: "anna", Key: "anna-key-1"}, {Title: "bad title", Key: "bob-key-1"}}
		}), wantErr: "secure.credentials[1].title"},
		{name: "and the key rules", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Credentials = []v1.SecureCredential{{Title: "anna", Key: "abc"}}
		}), wantErr: "secure.credentials[0].key"},
		{name: "a login titled like the sign-in form's fields", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Credentials = []v1.SecureCredential{{Title: "frp_key", Key: "anna-key-1"}}
		}), wantErr: "sign-in form"},
		{name: "authorization stays reserved for every login", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.Methods = []string{"basic"}
			b.Secure.Credentials = []v1.SecureCredential{{Title: "Authorization", Key: "anna-key-1"}}
		}), wantErr: "secure.credentials[0].title"},
		{name: "negative unlock", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.UnlockSeconds = -1
		}), wantErr: "unlockSeconds"},
		{name: "addresses and networks", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.AllowIPs = []string{"10.0.0.0/8", "2001:db8::/32"}
			b.Secure.TrustedIPs = []string{"192.0.2.7"}
		})},
		{name: "a bad address", base: secureBase("tcp", func(b *v1.ProxyBaseConfig) {
			b.Secure.TrustedIPs = []string{"192.0.2.300"}
		}), wantErr: "secure.trustedIPs"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSecureConfig(tc.base)
			if tc.wantErr == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

// basic and bearer read the Authorization header, which an http proxy's own
// basic authentication reads too; one of the two would always lose.
func TestSecureBasicAndBearerRefuseHTTPAuth(t *testing.T) {
	httpProxy := func(methods []string, edit func(*v1.HTTPProxyConfig)) *v1.HTTPProxyConfig {
		c := &v1.HTTPProxyConfig{}
		c.Type = "http"
		c.Secure = v1.SecureConfig{Enable: true, Title: "dangnhap", Key: "secret123", Methods: methods}
		if edit != nil {
			edit(c)
		}
		return c
	}
	withUser := func(c *v1.HTTPProxyConfig) { c.HTTPUser, c.HTTPPassword = "u", "p" }
	withRoute := func(c *v1.HTTPProxyConfig) { c.RouteByHTTPUser = "u" }

	require.NoError(t, validateSecureHTTPAuth(httpProxy([]string{"basic"}, nil)))
	require.NoError(t, validateSecureHTTPAuth(httpProxy(nil, withUser)), "the defaults leave Authorization alone")
	require.NoError(t, validateSecureHTTPAuth(httpProxy([]string{"header", "form"}, withUser)))
	require.ErrorContains(t, validateSecureHTTPAuth(httpProxy([]string{"basic"}, withUser)), "httpUser")
	require.ErrorContains(t, validateSecureHTTPAuth(httpProxy([]string{"bearer"}, withUser)), "httpUser")
	require.ErrorContains(t, validateSecureHTTPAuth(httpProxy([]string{"link", "basic"}, withRoute)), "routeByHTTPUser")

	off := httpProxy([]string{"basic"}, withUser)
	off.Secure.Enable = false
	require.NoError(t, validateSecureHTTPAuth(off), "secure access off is nobody's business")
}
