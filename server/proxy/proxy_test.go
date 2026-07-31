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
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/proto/wire"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/fatedier/frp/server/controller"
	"github.com/fatedier/frp/server/visitor"
)

func TestWorkConnStartWritesStartWorkConn(t *testing.T) {
	client, server := net.Pipe()

	defer client.Close()

	defer server.Close()

	serverMsgConn := msg.NewConn(server, msg.NewV2ReadWriter(server))

	clientMsgConn := msg.NewConn(client, msg.NewV2ReadWriter(client))

	workConn := NewWorkConn(serverMsgConn)

	in := &msg.StartWorkConn{ProxyName: "tcp", SrcAddr: "127.0.0.1", SrcPort: 1234}

	type startResult struct {
		conn net.Conn

		err error
	}

	resultCh := make(chan startResult, 1)

	go func() {
		conn, err := workConn.Start(in)

		resultCh <- startResult{conn: conn, err: err}
	}()

	out, err := clientMsgConn.ReadMsg()

	require.NoError(t, err)

	require.Equal(t, in, out)

	result := <-resultCh

	require.NoError(t, result.err)

	require.Same(t, serverMsgConn, result.conn)
}

func TestGetWorkConnFromPoolStartWorkConnUnchangedForUDPWireV2(t *testing.T) {
	startMsg := getStartWorkConnFromPool(t, &v1.UDPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "udp", Type: string(v1.ProxyTypeUDP)},
	}, wire.ProtocolV2)

	require.Equal(t, msg.StartWorkConn{ProxyName: "udp"}, startMsg)
}

func TestGetWorkConnFromPoolLeavesRawTCPPayloadUnframed(t *testing.T) {
	startMsg := getStartWorkConnFromPool(t, &v1.TCPProxyConfig{
		ProxyBaseConfig: v1.ProxyBaseConfig{Name: "tcp", Type: string(v1.ProxyTypeTCP)},
	}, wire.ProtocolV2)

	require.Equal(t, msg.StartWorkConn{ProxyName: "tcp"}, startMsg)
}

func getStartWorkConnFromPool(t *testing.T, cfg v1.ProxyConfigurer, wireProtocol string) msg.StartWorkConn {
	t.Helper()

	client, server := net.Pipe()

	t.Cleanup(func() {
		client.Close()

		server.Close()
	})

	serverMsgConn := msg.NewConn(server, msg.NewV2ReadWriter(server))

	clientMsgConn := msg.NewConn(client, msg.NewV2ReadWriter(client))

	pxy := &BaseProxy{
		name: cfg.GetBaseConfig().Name,

		configurer: cfg,

		poolCount: 0,

		ctx: context.Background(),

		wireProtocol: wireProtocol,

		getWorkConnFn: func() (*WorkConn, error) {
			return NewWorkConn(serverMsgConn), nil
		},
	}

	errCh := make(chan error, 1)

	go func() {
		conn, err := pxy.GetWorkConnFromPool(nil, nil)

		if conn != nil {
			conn.Close()
		}

		errCh <- err
	}()

	var startMsg msg.StartWorkConn

	require.NoError(t, clientMsgConn.ReadMsgInto(&startMsg))

	require.NoError(t, <-errCh)

	return startMsg
}

// Visitor-based proxies authenticate with a shared secret before their traffic
// reaches handleUserTCPConnection, so they are exempt from rate limiting. The
// exemption is set where the visitor listener is created rather than matched
// against a list of type names, which is what this pins down: add another
// visitor type and it is covered without touching the firewall code.
func TestStartVisitorListenerMarksProxyAuthenticated(t *testing.T) {
	pxy := &BaseProxy{
		name: "secret-tunnel",
		rc:   &controller.ResourceController{VisitorManager: visitor.NewManager()},
		ctx:  context.Background(),
		xl:   xlog.New(),
	}
	require.False(t, pxy.visitorAuthenticated, "a proxy starts out subject to rate limiting")

	require.NoError(t, pxy.startVisitorListener("sk", []string{"bob"}, "stcp"))
	require.True(t, pxy.visitorAuthenticated,
		"a visitor listener must exempt its proxy: the secret already identifies the caller")

	for _, l := range pxy.listeners {
		_ = l.Close()
	}
}

// The ordinary types keep their limits - the exemption must not leak to
// anything that never proved a secret.
func TestPlainProxyIsNotVisitorAuthenticated(t *testing.T) {
	require.False(t, (&BaseProxy{}).visitorAuthenticated)
}
