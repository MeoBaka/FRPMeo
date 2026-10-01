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
	"errors"
	"net"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

// readBanner dials the gateway and reads what it says first. The ssh server
// announces itself before anything else, so a banner says the handshake began
// and its absence says the connection was dropped before it could.
//
// A refusal on loopback can arrive as a reset before the dial has finished, so
// a dial that fails with one reads as no banner rather than failing the test.
func readBanner(t *testing.T, addr string) string {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		if errors.Is(err, syscall.ECONNRESET) {
			return ""
		}
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	return string(buf[:n])
}

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
			var askedPort atomic.Int32
			g, err := NewGateway(v1.SSHTunnelGateway{BindPort: 0}, "127.0.0.1",
				netpkg.NewInternalListener(),
				func(_ string, port int) (bool, string) {
					asked.Add(1)
					askedPort.Store(int32(port))
					return tc.allow, "rule test"
				})
			if err != nil {
				t.Fatalf("new gateway: %v", err)
			}
			go g.Run()
			t.Cleanup(func() { _ = g.Close() })

			banner := readBanner(t, g.ln.Addr().String())
			gotBanner := strings.HasPrefix(banner, "SSH-")
			if gotBanner != tc.wantBanner {
				t.Fatalf("ssh banner present = %v, want %v (read %q)", gotBanner, tc.wantBanner, banner)
			}

			// The refusal can reach the client before Run returns from the
			// check, so give the count a moment rather than racing it.
			deadline := time.Now().Add(time.Second)
			for asked.Load() == 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if got := asked.Load(); got != 1 {
				t.Fatalf("firewall asked %d times, want once", got)
			}
			// A rule names the port the peer dialed, which for a gateway bound
			// to port 0 is the one the system picked.
			if want := g.ln.Addr().(*net.TCPAddr).Port; int(askedPort.Load()) != want {
				t.Fatalf("firewall was told port %d, want %d", askedPort.Load(), want)
			}
		})
	}
}

// With no firewall configured the gateway is handed a nil check, and has to
// carry on rather than turn everyone away.
func TestGatewayWithoutFirewallLetsPeersIn(t *testing.T) {
	g, err := NewGateway(v1.SSHTunnelGateway{BindPort: 0}, "127.0.0.1", netpkg.NewInternalListener(), nil)
	if err != nil {
		t.Fatalf("new gateway: %v", err)
	}
	go g.Run()
	t.Cleanup(func() { _ = g.Close() })

	if banner := readBanner(t, g.ln.Addr().String()); !strings.HasPrefix(banner, "SSH-") {
		t.Fatalf("expected the ssh handshake to start, read %q", banner)
	}
}
