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

package vhost

import (
	"io"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

// The unlock link of a secure mc proxy is an HTTP request on the game port. It
// has to be routed to the proxy it names, and arrive there whole, so the
// proxy's gate can read the key out of it.
func TestMinecraftMuxerRoutesHTTPRequestsByHost(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	req := "GET /?dangnhap=secret123 HTTP/1.1\r\nHost: play.example.com:25565\r\n\r\n"
	go func() { _, _ = client.Write([]byte(req)) }()

	sc, info, err := GetMinecraftHostname(server)
	require.NoError(t, err)
	require.Equal(t, "play.example.com", info["Host"])

	buf := make([]byte, len(req))
	_, err = io.ReadFull(sc, buf)
	require.NoError(t, err)
	require.Equal(t, req, string(buf))
}

func TestMinecraftMuxerStillRoutesHandshakes(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	// packet id 0, protocol 767, "mc.example.com", port 25565, next state 2
	host := "mc.example.com"
	payload := append([]byte{0x00, 0xff, 0x05, byte(len(host))}, host...)
	payload = append(payload, 0x63, 0xdd, 0x02)
	handshake := append([]byte{byte(len(payload))}, payload...)
	go func() { _, _ = client.Write(handshake) }()

	sc, info, err := GetMinecraftHostname(server)
	require.NoError(t, err)
	require.Equal(t, host, info["Host"])

	buf := make([]byte, len(handshake))
	_, err = io.ReadFull(sc, buf)
	require.NoError(t, err)
	require.Equal(t, handshake, buf, "the backend still receives the handshake intact")
}
