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
	// SecureMethodLink takes the key from the URL query: ?<title>=<key>, a
	// link opened once.
	SecureMethodLink = "link"

	// SecureMethodBasic asks for it the way a site asks for a username and a
	// password - the browser's own sign-in prompt, or any client's basic
	// authentication - with the title as the username and the key as the
	// password.
	SecureMethodBasic = "basic"

	// SecureMethodHeader takes it from a request header "<title>: <key>", on
	// any request method.
	SecureMethodHeader = "header"

	// SecureMethodForm takes it from a field <title> of a form body, which is
	// what a POST from an HTML form sends.
	SecureMethodForm = "form"

	// SecureMethodJSON takes it from a field <title> of a JSON body.
	SecureMethodJSON = "json"

	// SecureMethodBearer takes it from "Authorization: Bearer <key>", where API
	// clients send an API key.
	SecureMethodBearer = "bearer"

	// SecureMethodHTTP is header, form and json together: the single switch
	// the first version had, kept so the configs written for it mean the same.
	SecureMethodHTTP = "http"

	// SecureMethodLine takes it from the first line of a raw TCP connection,
	// "<title>: <key>", or from a UDP datagram carrying exactly that line.
	SecureMethodLine = "line"
)

// The fields frps' own sign-in form sends a title and a key under - in the
// query for link, in the body for form and json - besides a field named after
// the title itself.
const (
	SecureFormTitleField = "frp_title"
	SecureFormKeyField   = "frp_key"
)

// SecureMethods lists every method name a config may use.
var SecureMethods = []string{
	SecureMethodLink, SecureMethodBasic, SecureMethodHeader, SecureMethodForm,
	SecureMethodJSON, SecureMethodBearer, SecureMethodHTTP, SecureMethodLine,
}

// DefaultSecureMethods is what an empty SecureConfig.Methods means: what the
// first version offered. basic and bearer are only on when named - basic
// changes what a browser sees first, and bearer takes a header the backend may
// want for itself.
var DefaultSecureMethods = []string{SecureMethodLink, SecureMethodHTTP, SecureMethodLine}

// firstSecureMethods are the method names an frps without
// msg.FeatureSecureMethods understands.
var firstSecureMethods = []string{SecureMethodLink, SecureMethodHTTP, SecureMethodLine}

// NewerSecureMethods returns the methods in methods that an frps without
// msg.FeatureSecureMethods would refuse as unknown.
func NewerSecureMethods(methods []string) []string {
	var out []string
	for _, m := range methods {
		if !slices.Contains(firstSecureMethods, m) && !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// Defaults for the SecureConfig fields where 0 means "the default".
const (
	DefaultSecureUnlockSeconds        = 12 * 60 * 60
	DefaultSecureMaxFailures          = 5
	DefaultSecureMaxAttemptsPerMinute = 30
	DefaultSecureBanSeconds           = 600
)

// SecureConfig locks a proxy behind a key. A visitor has to present
// "<title>: <key>" - by link, at a sign-in prompt, in an HTTP request, or as
// the first line of the connection - before frps forwards anything to the
// backend; everyone else is refused. frps enforces it, so it covers every
// public proxy type.
type SecureConfig struct {
	Enable bool `json:"enable,omitempty"`

	// Title is the custom name the key travels under: the header, query
	// parameter, form field or line prefix. For example "auth" or "dangnhap".
	Title string `json:"title,omitempty"`

	// Key is the secret itself - the "custom desc".
	Key string `json:"key,omitempty"`

	// Credentials are more title/key pairs that open the proxy, each a login
	// of its own - one per person, say, so one can be taken away without
	// changing everybody else's. Title and Key above are the first.
	Credentials []SecureCredential `json:"credentials,omitempty"`

	// Methods selects how the key may be presented: "link", "basic",
	// "header", "form", "json", "bearer" and "line" - "http" being header, form
	// and json together. Empty means DefaultSecureMethods: link, http and line.
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

// SecureCredential is one title/key pair: a username and a password, in the
// terms of a sign-in prompt.
type SecureCredential struct {
	Title string `json:"title,omitempty"`
	Key   string `json:"key,omitempty"`
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
	out.Credentials = slices.Clone(c.Credentials)
	out.Methods = slices.Clone(c.Methods)
	out.AllowIPs = slices.Clone(c.AllowIPs)
	out.TrustedIPs = slices.Clone(c.TrustedIPs)
	return out
}

// AllCredentials is every title/key pair that opens the proxy: Title and Key,
// then Credentials.
func (c *SecureConfig) AllCredentials() []SecureCredential {
	out := make([]SecureCredential, 0, 1+len(c.Credentials))
	out = append(out, SecureCredential{Title: c.Title, Key: c.Key})
	return append(out, c.Credentials...)
}

// HasMethod reports whether the key may be presented by method m.
func (c *SecureConfig) HasMethod(m string) bool {
	methods := c.Methods
	if len(methods) == 0 {
		methods = DefaultSecureMethods
	}
	if slices.Contains(methods, m) {
		return true
	}
	switch m {
	case SecureMethodHeader, SecureMethodForm, SecureMethodJSON:
		return slices.Contains(methods, SecureMethodHTTP)
	}
	return false
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
	var creds []msg.ProxySecureCredential
	for _, cr := range c.Credentials {
		creds = append(creds, msg.ProxySecureCredential{Title: cr.Title, Key: cr.Key})
	}
	return &msg.ProxySecure{
		Title:                c.Title,
		Key:                  c.Key,
		Credentials:          creds,
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
	var creds []SecureCredential
	for _, cr := range m.Credentials {
		creds = append(creds, SecureCredential{Title: cr.Title, Key: cr.Key})
	}
	return SecureConfig{
		Enable:        true,
		Title:         m.Title,
		Key:           m.Key,
		Credentials:   creds,
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
