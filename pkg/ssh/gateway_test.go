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
	"testing"
	"time"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

// A peer that reaches the gateway's port is met by the ssh server itself: the
// banner is the first thing it reads.
func TestGatewayStartsTheSSHHandshake(t *testing.T) {
	g, err := NewGateway(v1.SSHTunnelGateway{BindPort: 0}, "127.0.0.1", netpkg.NewInternalListener())
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
