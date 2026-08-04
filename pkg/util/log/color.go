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

package log

import (
	"os"
)

// colorUsable reports whether writing ANSI escapes to f will produce color
// rather than garbage.
//
// Color is worth having on a terminal and worth nothing anywhere else, and
// "anywhere else" is most of where frps output actually goes:
//
//   - Redirected to a file or piped to another program, the escapes are stored
//     verbatim. Every later reader - grep, an editor, a log shipper - then has
//     to know to strip them, and the ones that do not show `[1;34m` in front of
//     every line.
//   - On a Windows console without virtual terminal processing the escapes are
//     printed rather than interpreted, which is the same mess on screen. That
//     is not only old Windows: a console handle inherited from a service
//     manager or a wrapper process often has it off too.
//
// So the question is answered per run, from the handle actually being written
// to, rather than assumed.
func colorUsable(f *os.File) bool {
	if f == nil {
		return false
	}

	// NO_COLOR is honored by convention: set to anything, it means the caller
	// wants plain text. https://no-color.org
	if v, ok := os.LookupEnv("NO_COLOR"); ok && v != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}

	info, err := f.Stat()
	if err != nil {
		return false
	}
	// Not a terminal - a file, a pipe, a socket. Whatever reads it later is not
	// going to interpret escapes.
	if info.Mode()&os.ModeCharDevice == 0 {
		return false
	}

	return enableVirtualTerminal(f)
}
