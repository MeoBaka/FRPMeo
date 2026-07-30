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

package ssh

import (
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

// The gateway opens a port of its own, which no other part of frps guards. A
// peer the firewall has turned away at the control port must not find a second
// door standing open here.
func TestGatewayAsksBeforeTheHandshake(t *testing.T) {
	for _, tc := range []struct {
		name       string
		allow      bool
		wantBanner bool
	}{
		{name: "rejected", allow: false, wantBanner: false},
		{name: "allowed", allow: true, wantBanner: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var asked atomic.Int32
			g, err := NewGateway(v1.SSHTunnelGateway{BindPort: 0}, "127.0.0.1",
				netpkg.NewInternalListener(),
				func(_ string, _ int) (bool, string) {
					asked.Add(1)
					return tc.allow, "rule test"
				})
			if err != nil {
				t.Fatalf("new gateway: %v", err)
			}
			go g.Run()
			t.Cleanup(func() { _ = g.Close() })

			conn, err := net.Dial("tcp", g.ln.Addr().String())
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			// The ssh server announces itself before anything else, so the
			// banner is what says the handshake began. Its absence is what
			// says the connection was dropped before it could.
			_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			buf := make([]byte, 64)
			n, _ := conn.Read(buf)
			gotBanner := strings.HasPrefix(string(buf[:n]), "SSH-")

			if asked.Load() != 1 {
				t.Fatalf("firewall asked %d times, want once", asked.Load())
			}
			if gotBanner != tc.wantBanner {
				t.Fatalf("ssh banner present = %v, want %v (read %q)", gotBanner, tc.wantBanner, buf[:n])
			}
		})
	}
}

// With no firewall configured the gateway is handed a nil check, and has to
// carry on rather than turn everyone away.
func TestGatewayWithoutFirewallLetsPeersIn(t *testing.T) {
	g, err := NewGateway(v1.SSHTunnelGateway{BindPort: 0}, "127.0.0.1",
		netpkg.NewInternalListener(), nil)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	go g.Run()
	t.Cleanup(func() { _ = g.Close() })

	conn, err := net.Dial("tcp", g.ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "SSH-") {
		t.Fatalf("expected the ssh handshake to start, read %q", buf[:n])
	}
}
