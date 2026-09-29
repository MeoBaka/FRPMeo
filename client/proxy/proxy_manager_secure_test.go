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

package proxy

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/fatedier/frp/client/event"
	"github.com/fatedier/frp/pkg/msg"
)

// An frps that does not advertise secure access would drop the settings and
// serve the proxy with no lock on it, so the proxy is never sent to one.
func TestASecureProxyIsNotSentToAnFrpsWithoutTheFeature(t *testing.T) {
	pm := &Manager{}
	pm.SetServerFeatures([]string{"something-else"})

	err := pm.HandleEvent(&event.StartProxyPayload{NewProxyMsg: &msg.NewProxy{
		ProxyName: "p",
		Secure:    &msg.ProxySecure{Title: "auth", Key: "secret123"},
	}})

	require.ErrorIs(t, err, ErrSecureUnsupported)
	require.True(t, isSecureUnsupported(err), "the wrapper recognizes it and fails the start")
}

func TestTheFeatureIsReadFromTheLoginResponse(t *testing.T) {
	pm := &Manager{}
	require.False(t, pm.serverSecure.Load(), "no features until frps says so")

	pm.SetServerFeatures([]string{msg.FeatureSecureProxy})
	require.True(t, pm.serverSecure.Load())
}
