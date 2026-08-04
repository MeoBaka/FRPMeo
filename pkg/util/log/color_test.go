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
	"path/filepath"
	"testing"
)

// The case that put `[1;34m` in front of every line of a production log: the
// output was a file, and escapes written to a file are simply stored.
func TestColorIsOffWhenOutputIsAFile(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "frps.log"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	if colorUsable(f) {
		t.Error("color would be written to a file, where nothing interprets it")
	}
}

// A pipe is the other half of the same problem - `frps | tee`, or a service
// manager capturing stdout.
func TestColorIsOffWhenOutputIsAPipe(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	if colorUsable(w) {
		t.Error("color would be written to a pipe")
	}
}

func TestColorIsOffWithoutAnOutput(t *testing.T) {
	if colorUsable(nil) {
		t.Error("a nil file was reported as able to show color")
	}
}

// Both are conventions a user reaches for when a tool is painting their
// terminal and they want it to stop.
func TestColorHonoursTheEnvironment(t *testing.T) {
	f, err := os.Create(filepath.Join(t.TempDir(), "frps.log"))
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	defer f.Close()

	t.Setenv("NO_COLOR", "1")
	if colorUsable(f) {
		t.Error("NO_COLOR was ignored")
	}

	t.Setenv("NO_COLOR", "")
	t.Setenv("TERM", "dumb")
	if colorUsable(f) {
		t.Error("TERM=dumb was ignored")
	}
}
