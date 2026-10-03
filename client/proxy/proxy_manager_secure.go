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
	"strings"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
)

// ErrSecureUnsupported is returned for a secure proxy when frps did not
// advertise msg.FeatureSecureProxy at login. Such a server ignores the secure
// settings, so sending it the proxy would expose the proxy unlocked.
var ErrSecureUnsupported = errors.New("frps does not support secure access; update frps before enabling it on this proxy")

func isSecureUnsupported(err error) bool {
	return errors.Is(err, ErrSecureUnsupported)
}

// secureFeatureError is returned for a secure proxy using something this frps
// did not advertise: methods without msg.FeatureSecureMethods, more than one
// title/key without msg.FeatureSecureCredentials. Neither would expose the
// proxy - the frps refuses the one and ignores the other - so this is about
// saying what to update before anybody wonders why a login does not work. It
// counts as ErrSecureUnsupported, so it fails the start the same way.
type secureFeatureError struct {
	what string
}

func (e *secureFeatureError) Error() string {
	return "frps does not support " + e.what + "; update frps before using it on this proxy"
}

func (e *secureFeatureError) Is(target error) bool {
	return target == ErrSecureUnsupported
}

// SetServerFeatures records what frps advertised at login. Call it before the
// proxies start.
func (pm *Manager) SetServerFeatures(features []string) {
	pm.serverSecure.Store(slices.Contains(features, msg.FeatureSecureProxy))
	pm.serverSecureMethods.Store(slices.Contains(features, msg.FeatureSecureMethods))
	pm.serverSecureCredentials.Store(slices.Contains(features, msg.FeatureSecureCredentials))
}

// checkSecureFeatures fails a secure proxy that relies on something frps did
// not advertise.
func (pm *Manager) checkSecureFeatures(s *msg.ProxySecure) error {
	if s == nil {
		return nil
	}
	if !pm.serverSecureMethods.Load() {
		if newer := v1.NewerSecureMethods(s.Methods); len(newer) > 0 {
			return &secureFeatureError{what: "the secure methods " + strings.Join(newer, ", ")}
		}
	}
	if len(s.Credentials) > 0 && !pm.serverSecureCredentials.Load() {
		return &secureFeatureError{what: "more than one secure title/key"}
	}
	return nil
}

// IsSecure reports whether the named proxy has secure access switched on.
func (pm *Manager) IsSecure(name string) bool {
	pm.mu.RLock()
	pw, ok := pm.proxies[name]
	pm.mu.RUnlock()
	return ok && pw.Cfg.GetBaseConfig().Secure.Enable
}
