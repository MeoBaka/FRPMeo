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
	"errors"
	"slices"

	"github.com/fatedier/frp/pkg/msg"
)

// ErrSecureUnsupported is returned for a secure proxy when frps did not
// advertise msg.FeatureSecureProxy at login. Such a server ignores the secure
// settings, so sending it the proxy would expose the proxy unlocked.
var ErrSecureUnsupported = errors.New("frps does not support secure access; update frps before enabling it on this proxy")

func isSecureUnsupported(err error) bool {
	return errors.Is(err, ErrSecureUnsupported)
}

// SetServerFeatures records what frps advertised at login. Call it before the
// proxies start.
func (pm *Manager) SetServerFeatures(features []string) {
	pm.serverSecure.Store(slices.Contains(features, msg.FeatureSecureProxy))
}

// IsSecure reports whether the named proxy has secure access switched on.
func (pm *Manager) IsSecure(name string) bool {
	pm.mu.RLock()
	pw, ok := pm.proxies[name]
	pm.mu.RUnlock()
	return ok && pw.Cfg.GetBaseConfig().Secure.Enable
}
