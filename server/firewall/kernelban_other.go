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

//go:build !linux

package firewall

import "github.com/fatedier/frp/pkg/util/log"

// newPlatformBanSink has nothing to offer away from Linux.
//
// Windows can be made to drop addresses through the firewall API, but it has no
// per-entry deadline, so this process would have to track every ban's expiry
// and remove it - the bookkeeping ipset's timeout exists to avoid - and each
// change reloads the policy, which is far too slow to do per ban. It is
// buildable; it is not the same feature, and pretending otherwise in a log line
// would be worse than saying so.
func newPlatformBanSink(required bool) banSink {
	if required {
		log.Warnf("[FW] kernel ban is not available on this platform; bans are enforced in frps only")
	} else {
		log.Infof("[FW] kernel ban is not available on this platform; bans are enforced in frps only")
	}
	return noopSink{}
}
