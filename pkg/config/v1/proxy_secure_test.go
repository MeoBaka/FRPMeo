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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/pkg/msg"
)

func fullSecureConfig() SecureConfig {
	return SecureConfig{
		Enable:        true,
		Title:         "auth",
		Key:           "secret123",
		Credentials:   []SecureCredential{{Title: "anna", Key: "anna-key-1"}},
		Methods:       []string{SecureMethodLink, SecureMethodLine},
		UnlockSeconds: 60,
		AllowIPs:      []string{"10.0.0.0/8"},
		TrustedIPs:    []string{"192.0.2.7"},
		AntiSpam: SecureAntiSpamConfig{
			MaxFailures:          3,
			MaxAttemptsPerMinute: -1,
			BanSeconds:           30,
		},
	}
}

func TestSecureConfigSurvivesTheTripToFrps(t *testing.T) {
	in := &TCPProxyConfig{ProxyBaseConfig: ProxyBaseConfig{Name: "p", Type: "tcp", Secure: fullSecureConfig()}}

	var m msg.NewProxy
	in.MarshalToMsg(&m)
	out := &TCPProxyConfig{}
	out.UnmarshalFromMsg(&m)

	require.Equal(t, in.Secure, out.Secure)
}

func TestSecureOffSendsNothing(t *testing.T) {
	in := &TCPProxyConfig{ProxyBaseConfig: ProxyBaseConfig{Name: "p", Type: "tcp", Secure: SecureConfig{Title: "auth", Key: "secret123"}}}

	var m msg.NewProxy
	in.MarshalToMsg(&m)
	require.Nil(t, m.Secure, "a disabled lock is not sent; frps must not mistake it for an enabled one")

	out := &TCPProxyConfig{}
	out.UnmarshalFromMsg(&m)
	require.False(t, out.Secure.Enable)
}

func TestSecureCloneSharesNoLists(t *testing.T) {
	orig := ProxyBaseConfig{Secure: fullSecureConfig()}
	clone := orig.Clone()

	clone.Secure.Credentials[0].Key = "changed"
	clone.Secure.Methods[0] = "changed"
	clone.Secure.AllowIPs[0] = "changed"
	clone.Secure.TrustedIPs[0] = "changed"

	require.Equal(t, fullSecureConfig(), orig.Secure)
}

// An empty list means what the first version offered, so a config written for
// it keeps working the same: basic and bearer have to be asked for.
func TestSecureMethodsDefaultToTheFirstSet(t *testing.T) {
	c := SecureConfig{}
	for _, m := range []string{SecureMethodLink, SecureMethodHTTP, SecureMethodHeader, SecureMethodForm, SecureMethodJSON, SecureMethodLine} {
		require.True(t, c.HasMethod(m), m)
	}
	for _, m := range []string{SecureMethodBasic, SecureMethodBearer} {
		require.False(t, c.HasMethod(m), "%s is opt-in", m)
	}

	c.Methods = []string{SecureMethodLink}
	require.True(t, c.HasMethod(SecureMethodLink))
	require.False(t, c.HasMethod(SecureMethodLine))
	require.False(t, c.HasMethod(SecureMethodHeader))
}

// "http" is the first version's name for header, form and json together; the
// three can now also be chosen one at a time.
func TestSecureHTTPMeansHeaderFormAndJSON(t *testing.T) {
	c := SecureConfig{Methods: []string{SecureMethodHTTP}}
	for _, m := range []string{SecureMethodHeader, SecureMethodForm, SecureMethodJSON} {
		require.True(t, c.HasMethod(m), m)
	}
	require.False(t, c.HasMethod(SecureMethodBasic))
	require.False(t, c.HasMethod(SecureMethodLink))

	c.Methods = []string{SecureMethodForm, SecureMethodBasic}
	require.True(t, c.HasMethod(SecureMethodForm))
	require.True(t, c.HasMethod(SecureMethodBasic))
	require.False(t, c.HasMethod(SecureMethodHeader))
	require.False(t, c.HasMethod(SecureMethodJSON))
	require.False(t, c.HasMethod(SecureMethodHTTP), "one of the three is not all of them")
}

// What an frps from before the newer methods would not know.
func TestNewerSecureMethods(t *testing.T) {
	require.Empty(t, NewerSecureMethods(nil))
	require.Empty(t, NewerSecureMethods([]string{SecureMethodLink, SecureMethodHTTP, SecureMethodLine}))
	require.Equal(t, []string{SecureMethodBasic, SecureMethodForm},
		NewerSecureMethods([]string{SecureMethodLink, SecureMethodBasic, SecureMethodForm, SecureMethodBasic}))
}

func TestAllCredentialsStartsWithTitleAndKey(t *testing.T) {
	c := fullSecureConfig()
	require.Equal(t, []SecureCredential{{Title: "auth", Key: "secret123"}, {Title: "anna", Key: "anna-key-1"}}, c.AllCredentials())

	c.Credentials = nil
	require.Equal(t, []SecureCredential{{Title: "auth", Key: "secret123"}}, c.AllCredentials())
}
