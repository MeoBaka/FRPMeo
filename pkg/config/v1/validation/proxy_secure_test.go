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
