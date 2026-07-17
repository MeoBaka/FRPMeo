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

package server

import (
	"context"
	"net"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/fatedier/frp/server/controller"
	"github.com/fatedier/frp/server/proxy"
	"github.com/fatedier/frp/server/registry"
)

func newTestControl(t *testing.T, runID string) *Control {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { c1.Close(); c2.Close() })

	serverCfg := &v1.ServerConfig{}
	serverCfg.Complete()

	ctl, err := NewControl(xlog.NewContext(context.Background(), xlog.New()), &SessionContext{
		RC:             &controller.ResourceController{},
		PxyManager:     proxy.NewManager(),
		PluginManager:  plugin.NewManager(),
		Conn:           msg.NewConn(c1, msg.NewReadWriter(c1, "")),
		LoginMsg:       &msg.Login{RunID: runID},
		ServerCfg:      serverCfg,
		ClientRegistry: registry.NewClientRegistry(),
	})
	if err != nil {
		t.Fatalf("new control: %v", err)
	}
	return ctl
}

// waitClosed reports whether WaitClosed returns at all. Generous, because a
// pass must mean "released" and never "the machine was busy" - the bug it
// guards blocks forever, so no real wait is close to this.
func waitClosed(t *testing.T, ctl *Control) bool {
	t.Helper()
	done := make(chan struct{})
	go func() {
		ctl.WaitClosed()
		close(done)
	}()
	select {
	case <-done:
		return true
	case <-time.After(3 * time.Second):
		return false
	}
}

// A control can be replaced before it is ever started: RegisterControl waits on
// the old control while the new one's Start() only runs once RegisterControl has
// returned. doneCh used to be closed only at the end of worker(), which only
// runs from Start() - so replacing a control that never started left WaitClosed
// blocked for the life of the process, holding a goroutine and the whole session
// behind it, once per login attempt.
//
// This is what a client whose connection died silently does: it re-logins with
// the same run id, and the reconnect wedges.
func TestReplacedBeforeStartClosesDone(t *testing.T) {
	old := newTestControl(t, "run-1")
	replacement := newTestControl(t, "run-1")

	old.Replaced(replacement)

	if !waitClosed(t, old) {
		t.Fatal("WaitClosed never returned for a control replaced before Start; every silent reconnect leaks a goroutine")
	}
}

// The ordinary path: a control that started, then got replaced, still unwinds.
func TestReplacedAfterStartClosesDone(t *testing.T) {
	old := newTestControl(t, "run-2")
	replacement := newTestControl(t, "run-2")

	old.Start()
	time.Sleep(100 * time.Millisecond) // let worker() get going
	old.Replaced(replacement)

	if !waitClosed(t, old) {
		t.Fatal("WaitClosed never returned for a started control that was replaced")
	}
}

// Replacing twice must not panic on a second close of doneCh.
func TestReplacedTwiceDoesNotPanic(t *testing.T) {
	old := newTestControl(t, "run-3")
	a := newTestControl(t, "run-3")
	b := newTestControl(t, "run-3")

	old.Replaced(a)
	old.Replaced(b)

	if !waitClosed(t, old) {
		t.Fatal("WaitClosed never returned")
	}
}

// Start() after a replacement must not bring the worker up: it would close
// doneCh a second time on exit, and run a session that has already been handed
// over.
func TestStartAfterReplacedIsIgnored(t *testing.T) {
	old := newTestControl(t, "run-4")
	replacement := newTestControl(t, "run-4")

	old.Replaced(replacement)
	old.Start() // must be a no-op, and must not panic

	if !waitClosed(t, old) {
		t.Fatal("WaitClosed never returned")
	}
	// Give a worker that wrongly started time to reach its close(doneCh).
	time.Sleep(300 * time.Millisecond)
}
