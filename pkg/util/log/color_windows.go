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

//go:build windows

package log

import (
	"os"

	"golang.org/x/sys/windows"
)

// enableVirtualTerminal turns on the console mode that makes Windows interpret
// ANSI escapes instead of printing them, and reports whether it is on.
//
// It has to be asked for: a Windows console starts without it, and writing
// escapes to one that has not enabled it puts `[1;34m` on screen in front of
// every line. Consoles too old to support it - and handles that are consoles
// only in name, which is what a service wrapper often hands down - fail here,
// and failing is the answer: no color beats unreadable color.
//
// The mode is left on. It is process-wide state on the console we were given,
// and anything else writing escapes to the same console wants it too.
func enableVirtualTerminal(f *os.File) bool {
	handle := windows.Handle(f.Fd())

	var mode uint32
	if err := windows.GetConsoleMode(handle, &mode); err != nil {
		return false
	}
	if mode&windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING != 0 {
		return true
	}
	if err := windows.SetConsoleMode(handle, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING); err != nil {
		return false
	}

	return true
}
