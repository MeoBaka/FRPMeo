// Copyright 2023 The frp Authors

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
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"golang.org/x/crypto/ssh"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/transport"
	"github.com/fatedier/frp/pkg/util/log"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

// AllowFunc decides whether a peer may open an ssh connection at all. It is

// handed in rather than reached for: the firewall lives in the server, and the

// gateway has no business knowing about it.

//

// remoteAddr is the peer, port the gateway port it arrived on, so a rule can

// name that port like any other.

//

// An empty reason on a rejection means "do not log this one". Rate limiting

// uses it: rejections there arrive in bulk by definition, and a line each would

// turn a flood being refused into a flood of its own against the disk.

type AllowFunc func(remoteAddr string, port int) (ok bool, reason string)

type Gateway struct {
	bindPort int

	ln net.Listener

	peerServerListener *netpkg.InternalListener

	sshConfig *ssh.ServerConfig

	// allow is consulted before anything is read from a peer. nil means no

	// firewall is configured, and every peer is let through.

	allow AllowFunc

	// handshakeByteLimit is read per connection so a change made through the
	// dashboard reaches the next peer, not the next restart.
	handshakeByteLimit func() int
}

func NewGateway(
	cfg v1.SSHTunnelGateway, bindAddr string,

	peerServerListener *netpkg.InternalListener,

	allow AllowFunc,
) (*Gateway, error) {
	sshConfig := &ssh.ServerConfig{}

	// privateKey

	var (
		privateKeyBytes []byte

		err error
	)

	if cfg.PrivateKeyFile != "" {
		privateKeyBytes, err = os.ReadFile(cfg.PrivateKeyFile)
	} else {

		if cfg.AutoGenPrivateKeyPath != "" {
			privateKeyBytes, _ = os.ReadFile(cfg.AutoGenPrivateKeyPath)
		}

		if len(privateKeyBytes) == 0 {

			privateKeyBytes, err = transport.NewRandomPrivateKey()

			if err == nil && cfg.AutoGenPrivateKeyPath != "" {
				err = os.WriteFile(cfg.AutoGenPrivateKeyPath, privateKeyBytes, 0o600)
			}

		}

	}

	if err != nil {
		return nil, err
	}

	privateKey, err := ssh.ParsePrivateKey(privateKeyBytes)
	if err != nil {
		return nil, err
	}

	sshConfig.AddHostKey(privateKey)

	sshConfig.NoClientAuth = cfg.AuthorizedKeysFile == ""

	sshConfig.PublicKeyCallback = func(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		authorizedKeysMap, err := loadAuthorizedKeysFromFile(cfg.AuthorizedKeysFile)
		if err != nil {

			log.Errorf("load authorized keys file error: %v", err)

			return nil, fmt.Errorf("internal error")

		}

		user, ok := authorizedKeysMap[string(key.Marshal())]

		if !ok {
			return nil, fmt.Errorf("unknown public key for remoteAddr %q", conn.RemoteAddr())
		}

		return &ssh.Permissions{
			Extensions: map[string]string{
				"user": user,
			},
		}, nil
	}

	ln, err := net.Listen("tcp", net.JoinHostPort(bindAddr, strconv.Itoa(cfg.BindPort)))
	if err != nil {
		return nil, err
	}

	return &Gateway{
		bindPort: cfg.BindPort,

		ln: ln,

		allow: allow,

		peerServerListener: peerServerListener,

		sshConfig: sshConfig,
	}, nil
}

func (g *Gateway) Run() {
	for {

		conn, err := g.ln.Accept()
		if err != nil {
			return
		}

		// Before the ssh handshake, not after: this port reaches the same

		// tunneling as the control port, so a peer the firewall has turned

		// away there must not get a second door here.

		if g.allow != nil {
			if ok, reason := g.allow(conn.RemoteAddr().String(), g.bindPort); !ok {

				if reason != "" {
					log.Warnf("[FW] reject ssh %s reason: %s", conn.RemoteAddr(), reason)
				}

				// RST, so a refusal leaves no TIME_WAIT socket behind.

				netpkg.ArmReset(conn)

				conn.Close()

				continue

			}
		}

		go g.handleConn(conn)

	}
}

func (g *Gateway) Close() error {
	return g.ln.Close()
}

// SetHandshakeByteLimit installs the source of the per-connection ceiling on
// what a peer may send before its ssh handshake completes. Must be called
// before Run.
func (g *Gateway) SetHandshakeByteLimit(fn func() int) {
	g.handshakeByteLimit = fn
}

func (g *Gateway) handleConn(conn net.Conn) {
	defer conn.Close()

	ts, err := NewTunnelServer(conn, g.sshConfig, g.peerServerListener)
	if err != nil {
		return
	}
	if g.handshakeByteLimit != nil {
		ts.handshakeByteLimit = g.handshakeByteLimit()
	}

	if err := ts.Run(); err != nil {
		log.Errorf("ssh tunnel server run error: %v", err)
	}
}

func loadAuthorizedKeysFromFile(path string) (map[string]string, error) {
	authorizedKeysMap := make(map[string]string) // value is username

	authorizedKeysBytes, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	for len(authorizedKeysBytes) > 0 {

		pubKey, comment, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return nil, err
		}

		authorizedKeysMap[string(pubKey.Marshal())] = strings.TrimSpace(comment)

		authorizedKeysBytes = rest

	}

	return authorizedKeysMap, nil
}
