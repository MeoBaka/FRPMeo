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

package v1

import (
	"slices"

	"github.com/fatedier/frp/pkg/msg"
)

// The ways a visitor can present a secure proxy's key.
const (
	// SecureMethodLink takes the key from the URL query: ?<title>=<key>.
	SecureMethodLink = "link"

	// SecureMethodHTTP takes it from an HTTP header "<title>: <key>", or from
	// a field <title> in a form or JSON request body - a POST, PUT and so on.
	SecureMethodHTTP = "http"

	// SecureMethodLine takes it from the first line of a raw TCP connection,
	// "<title>: <key>", or from a UDP datagram carrying exactly that line.
	SecureMethodLine = "line"
)

// SecureMethods lists every method. An empty SecureConfig.Methods means all of
// them.
var SecureMethods = []string{SecureMethodLink, SecureMethodHTTP, SecureMethodLine}

// Defaults for the SecureConfig fields where 0 means "the default".
const (
	DefaultSecureUnlockSeconds        = 12 * 60 * 60
	DefaultSecureMaxFailures          = 5
	DefaultSecureMaxAttemptsPerMinute = 30
	DefaultSecureBanSeconds           = 600
)

// SecureConfig locks a proxy behind a key. A visitor has to present
// "<title>: <key>" - by link, by HTTP request, or as the first line of the
// connection - before frps forwards anything to the backend; everyone else is
// refused. frps enforces it, so it covers every public proxy type.
type SecureConfig struct {
	Enable bool `json:"enable,omitempty"`

	// Title is the custom name the key travels under: the header, query
	// parameter, form field or line prefix. For example "auth" or "dangnhap".
	Title string `json:"title,omitempty"`

	// Key is the secret itself - the "custom desc".
	Key string `json:"key,omitempty"`

	// Methods selects how the key may be presented: "link", "http" and "line".
	// Empty means all of them.
	Methods []string `json:"methods,omitempty"`

	// UnlockSeconds is how long a source IP stays unlocked after presenting
	// the key by link or HTTP request. 0 means 43200 (12 hours).
	UnlockSeconds int `json:"unlockSeconds,omitempty"`

	// AllowIPs, when set, are the only sources that may connect at all - with
	// a key or without. IPs or CIDRs.
	AllowIPs []string `json:"allowIPs,omitempty"`

	// TrustedIPs connect without a key. IPs or CIDRs.
	TrustedIPs []string `json:"trustedIPs,omitempty"`

	AntiSpam SecureAntiSpamConfig `json:"antiSpam,omitzero"`
}

// SecureAntiSpamConfig bans the sources that guess keys or hammer a secure
// proxy without one. In every field 0 means the default and a negative value
// switches that check off.
type SecureAntiSpamConfig struct {
	// MaxFailures bans a source after this many wrong keys. Default 5.
	MaxFailures int `json:"maxFailures,omitempty"`

	// MaxAttemptsPerMinute bans a source that tries this many times within a
	// minute without a valid key. Default 30.
	MaxAttemptsPerMinute int `json:"maxAttemptsPerMinute,omitempty"`

	// BanSeconds is how long a ban lasts. Default 600.
	BanSeconds int `json:"banSeconds,omitempty"`
}

func (c SecureConfig) Clone() SecureConfig {
	out := c
	out.Methods = slices.Clone(c.Methods)
	out.AllowIPs = slices.Clone(c.AllowIPs)
	out.TrustedIPs = slices.Clone(c.TrustedIPs)
	return out
}

// HasMethod reports whether the key may be presented by method m.
func (c *SecureConfig) HasMethod(m string) bool {
	return len(c.Methods) == 0 || slices.Contains(c.Methods, m)
}

// SecureLineApplies reports whether visitors of proxyType can present the key
// as the first line of a connection - or for udp and pe as a datagram. On http
// and https frps only ever sees an HTTP request or a TLS stream, and an mc
// connection is routed by the hostname in its handshake, which a key line lacks.
func SecureLineApplies(proxyType string) bool {
	switch ProxyType(proxyType) {
	case ProxyTypeHTTP, ProxyTypeHTTPS, ProxyTypeMC:
		return false
	}
	return true
}

func (c *SecureConfig) toMsg() *msg.ProxySecure {
	if !c.Enable {
		return nil
	}
	return &msg.ProxySecure{
		Title:                c.Title,
		Key:                  c.Key,
		Methods:              slices.Clone(c.Methods),
		UnlockSeconds:        c.UnlockSeconds,
		AllowIPs:             slices.Clone(c.AllowIPs),
		TrustedIPs:           slices.Clone(c.TrustedIPs),
		MaxFailures:          c.AntiSpam.MaxFailures,
		MaxAttemptsPerMinute: c.AntiSpam.MaxAttemptsPerMinute,
		BanSeconds:           c.AntiSpam.BanSeconds,
	}
}

func secureFromMsg(m *msg.ProxySecure) SecureConfig {
	if m == nil {
		return SecureConfig{}
	}
	return SecureConfig{
		Enable:        true,
		Title:         m.Title,
		Key:           m.Key,
		Methods:       slices.Clone(m.Methods),
		UnlockSeconds: m.UnlockSeconds,
		AllowIPs:      slices.Clone(m.AllowIPs),
		TrustedIPs:    slices.Clone(m.TrustedIPs),
		AntiSpam: SecureAntiSpamConfig{
			MaxFailures:          m.MaxFailures,
			MaxAttemptsPerMinute: m.MaxAttemptsPerMinute,
			BanSeconds:           m.BanSeconds,
		},
	}
}
