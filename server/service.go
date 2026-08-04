// Copyright 2017 fatedier, fatedier@gmail.com

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
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/fatedier/golib/crypto"
	"github.com/fatedier/golib/net/mux"
	fmux "github.com/hashicorp/yamux"
	quic "github.com/quic-go/quic-go"
	"github.com/samber/lo"

	"github.com/fatedier/frp/pkg/auth"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	modelmetrics "github.com/fatedier/frp/pkg/metrics"
	"github.com/fatedier/frp/pkg/msg"
	"github.com/fatedier/frp/pkg/nathole"
	plugin "github.com/fatedier/frp/pkg/plugin/server"
	"github.com/fatedier/frp/pkg/proto/wire"
	"github.com/fatedier/frp/pkg/ssh"
	"github.com/fatedier/frp/pkg/transport"
	httppkg "github.com/fatedier/frp/pkg/util/http"
	"github.com/fatedier/frp/pkg/util/log"
	netpkg "github.com/fatedier/frp/pkg/util/net"
	"github.com/fatedier/frp/pkg/util/tcpmux"
	"github.com/fatedier/frp/pkg/util/util"
	"github.com/fatedier/frp/pkg/util/version"
	"github.com/fatedier/frp/pkg/util/vhost"
	"github.com/fatedier/frp/pkg/util/xlog"
	"github.com/fatedier/frp/server/controller"
	"github.com/fatedier/frp/server/firewall"
	"github.com/fatedier/frp/server/group"
	"github.com/fatedier/frp/server/ports"
	"github.com/fatedier/frp/server/proxy"
	"github.com/fatedier/frp/server/registry"
	"github.com/fatedier/frp/server/visitor"
)

const (
	connReadTimeout time.Duration = 10 * time.Second

	connWriteTimeout time.Duration = 5 * time.Second

	vhostReadWriteTimeout time.Duration = 30 * time.Second
)

var errControlReplaced = errors.New("control was replaced during login")

func init() {
	crypto.DefaultSalt = "frp"

	// Disable quic-go's receive buffer warning.

	os.Setenv("QUIC_GO_DISABLE_RECEIVE_BUFFER_WARNING", "true")

	// Disable quic-go's ECN support by default. It may cause issues on certain operating systems.

	if os.Getenv("QUIC_GO_DISABLE_ECN") == "" {
		os.Setenv("QUIC_GO_DISABLE_ECN", "true")
	}
}

// Server service

type Service struct {
	// Dispatch connections to different handlers listen on same port

	muxer *mux.Mux

	// Accept connections from client

	listener net.Listener

	// Accept connections using kcp

	kcpListener net.Listener

	// Accept connections using quic

	quicListener *quic.Listener

	// Accept connections using websocket

	websocketListener net.Listener

	// Accept frp tls connections

	tlsListener net.Listener

	// Accept pipe connections from ssh tunnel gateway

	sshTunnelListener *netpkg.InternalListener

	// Manage all controllers

	ctlManager *ControlManager

	// Track logical clients keyed by user.clientID (runID fallback when raw clientID is empty).

	clientRegistry *registry.ClientRegistry

	// Manage all proxies

	pxyManager *proxy.Manager

	// Manage all plugins

	pluginManager *plugin.Manager

	// HTTP vhost router

	httpVhostRouter *vhost.Routers

	// All resource managers and controllers

	rc *controller.ResourceController

	// web server for dashboard UI and apis

	webServer *httppkg.Server

	sshTunnelGateway *ssh.Gateway

	// Auth runtime and encryption materials

	auth *auth.ServerAuth

	tlsConfig *tls.Config

	cfg *v1.ServerConfig

	// service context

	ctx context.Context

	// call cancel to stop service

	cancel context.CancelFunc
}

func NewService(cfg *v1.ServerConfig) (*Service, error) {
	tlsConfig, err := transport.NewServerTLSConfig(

		cfg.Transport.TLS.CertFile,

		cfg.Transport.TLS.KeyFile,

		cfg.Transport.TLS.TrustedCaFile)
	if err != nil {
		return nil, err
	}

	var webServer *httppkg.Server

	if cfg.WebServer.Port > 0 {

		ws, err := httppkg.NewServer(cfg.WebServer)
		if err != nil {
			return nil, err
		}

		webServer = ws

		modelmetrics.EnableMem()

		if cfg.EnablePrometheus {
			modelmetrics.EnablePrometheus()
		}

	}

	authRuntime, err := auth.BuildServerAuth(&cfg.Auth)
	if err != nil {
		return nil, err
	}

	clientRegistry := registry.NewClientRegistry()
	svr := &Service{
		ctlManager:     NewControlManager(clientRegistry),
		clientRegistry: clientRegistry,
		pxyManager:     proxy.NewManager(),
		pluginManager:  plugin.NewManager(),
		rc: &controller.ResourceController{
			VisitorManager: visitor.NewManager(),

			TCPPortManager: ports.NewManager("tcp", cfg.ProxyBindAddr, cfg.AllowPorts),

			UDPPortManager: ports.NewManager("udp", cfg.ProxyBindAddr, cfg.AllowPorts),
		},

		sshTunnelListener: netpkg.NewInternalListener(),

		httpVhostRouter: vhost.NewRouters(),

		auth: authRuntime,

		webServer: webServer,

		tlsConfig: tlsConfig,

		cfg: cfg,

		ctx: context.Background(),
	}

	if webServer != nil {
		webServer.RouteRegister(svr.registerRouteHandlers)
	}

	// Anti-bot layer for user connections (settings managed from the

	// dashboard, persisted to a JSON file next to frps).

	var fwErr error

	if svr.rc.Firewall, fwErr = firewall.New("frps_firewall.json"); fwErr != nil {
		return nil, fmt.Errorf("init firewall: %v", fwErr)
	}

	// The dashboard opens a port of its own, which nothing else guards.

	//

	// This has to come after the firewall exists, not with the rest of the

	// webServer setup above: svr.rc.Firewall is nil until the line above runs,

	// so a filter installed there would be skipped and the port would be left

	// open however the dashboard was configured.

	//

	// Decisions go to the firewall's own reporter rather than a log line each:

	// an exposed port is scanned continuously, and a line per probe would be

	// the same flood the firewall was turned on to stop.

	if webServer != nil && svr.rc.Firewall != nil {

		fw := svr.rc.Firewall

		// The same ceiling the control port applies, in the form net/http

		// offers: how much a peer may send before it has finished asking for

		// anything. Read once here rather than per connection, because

		// net/http takes it at construction - a later change through the

		// dashboard reaches the control port immediately and this one after a

		// restart.

		webServer.SetHandshakeByteLimit(fw.HandshakeByteLimit())

		webServer.SetConnFilter(func(remoteAddr string) bool {
			// The dashboard is a login form, so the rate limit is what answers
			// password guessing here.

			if v := fw.AdmitWeb(remoteAddr); !v.Allowed {
				fw.NoteDecision(firewall.SurfaceWeb, false, v.Reason, remoteAddr)

				return false
			}

			fw.NoteDecision(firewall.SurfaceWeb, true, "rate ok", remoteAddr)

			return true
		})

		// And a wrong password counts as a strike, which is the same evidence
		// as a wrong protocol on the control port: nobody who belongs here gets
		// it wrong again and again. The rate limit above still has to guess
		// where normal ends; this does not, so it is what actually stops a
		// guesser rather than slowing one down.

		webServer.SetOnAuthFail(func(remoteAddr string) {
			log.Debugf("[FW] dashboard login failed from %s", remoteAddr)

			svr.rc.Firewall.ReportProtocolFailure(remoteAddr)
		})

	}

	// Create tcpmux httpconnect multiplexer.

	if cfg.TCPMuxHTTPConnectPort > 0 {

		var l net.Listener

		address := net.JoinHostPort(cfg.ProxyBindAddr, strconv.Itoa(cfg.TCPMuxHTTPConnectPort))

		l, err = net.Listen("tcp", address)
		if err != nil {
			return nil, fmt.Errorf("create server listener error, %v", err)
		}

		svr.rc.TCPMuxHTTPConnectMuxer, err = tcpmux.NewHTTPConnectTCPMuxer(l, cfg.TCPMuxPassthrough, vhostReadWriteTimeout)
		if err != nil {
			return nil, fmt.Errorf("create vhost tcpMuxer error, %v", err)
		}

		log.Infof("tcpmux httpconnect multiplexer listen on %s, passthrough: %v", address, cfg.TCPMuxPassthrough)

	}

	// Init all plugins

	for _, p := range cfg.HTTPPlugins {

		svr.pluginManager.Register(plugin.NewHTTPPluginOptions(p))

		log.Infof("plugin [%s] has been registered", p.Name)

	}

	svr.rc.PluginManager = svr.pluginManager

	// Init group controller

	svr.rc.TCPGroupCtl = group.NewTCPGroupCtl(svr.rc.TCPPortManager)

	// Init HTTP group controller

	svr.rc.HTTPGroupCtl = group.NewHTTPGroupController(svr.httpVhostRouter)

	// Init TCP mux group controller

	svr.rc.TCPMuxGroupCtl = group.NewTCPMuxGroupCtl(svr.rc.TCPMuxHTTPConnectMuxer)

	// Init Minecraft group controller: opens a shared host-routing muxer per

	// public port that clients declare (mc proxy remotePort), no frps config.

	svr.rc.MinecraftGroupCtl = group.NewMinecraftGroupController(cfg.ProxyBindAddr, svr.rc.TCPPortManager, vhostReadWriteTimeout)

	// Init 404 not found page

	vhost.NotFoundPagePath = cfg.Custom404Page

	var (
		httpMuxOn bool

		httpsMuxOn bool
	)

	if cfg.BindAddr == cfg.ProxyBindAddr {

		if cfg.BindPort == cfg.VhostHTTPPort {
			httpMuxOn = true
		}

		if cfg.BindPort == cfg.VhostHTTPSPort {
			httpsMuxOn = true
		}

	}

	// Listen for accepting connections from client.

	address := net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.BindPort))

	ln, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("create server listener error, %v", err)
	}

	// The rate limit goes in front of the multiplexer rather than behind it.
	// Everything the multiplexer hands on has already had its opening bytes
	// read, under a timeout, on a goroutine spawned per connection without a
	// bound - so a check placed after it never sees a silent peer at all. See
	// firewall.GuardControl.

	// Unless the vhost muxers share this port, in which case nothing can be
	// decided here: the rest of what arrives is a tunneled site's visitors, and
	// the control rate limit is not sized for those. It goes on the control
	// listeners below instead, once the multiplexer has told the two apart.

	sharedWithVhost := httpMuxOn || httpsMuxOn

	if svr.rc.Firewall != nil && !sharedWithVhost {
		ln = svr.rc.Firewall.GuardControl(ln)
	}

	svr.muxer = mux.NewMux(ln)

	svr.muxer.SetKeepAlive(time.Duration(cfg.Transport.TCPKeepAlive) * time.Second)

	go func() {
		_ = svr.muxer.Serve()
	}()

	ln = svr.muxer.DefaultListener()

	svr.listener = ln

	log.Infof("frps tcp listen on %s", address)

	// Listen for accepting connections from client using kcp protocol.

	if cfg.KCPBindPort > 0 {

		address := net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.KCPBindPort))

		svr.kcpListener, err = netpkg.ListenKcp(address)
		if err != nil {
			return nil, fmt.Errorf("listen on kcp udp address %s error: %v", address, err)
		}

		// Guarded like the tcp port. It is the one other listener clients dial
		// directly, and it is not behind the multiplexer, so this is where its
		// firewall check lives now that admitAndServe no longer runs one.

		if svr.rc.Firewall != nil {
			svr.kcpListener = svr.rc.Firewall.GuardControl(svr.kcpListener)
		}

		log.Infof("frps kcp listen on udp %s", address)

	}

	if cfg.QUICBindPort > 0 {

		address := net.JoinHostPort(cfg.BindAddr, strconv.Itoa(cfg.QUICBindPort))

		quicTLSCfg := tlsConfig.Clone()

		quicTLSCfg.NextProtos = []string{"frp"}

		svr.quicListener, err = quic.ListenAddr(address, quicTLSCfg, &quic.Config{
			MaxIdleTimeout: time.Duration(cfg.Transport.QUIC.MaxIdleTimeout) * time.Second,

			MaxIncomingStreams: int64(cfg.Transport.QUIC.MaxIncomingStreams),

			KeepAlivePeriod: time.Duration(cfg.Transport.QUIC.KeepalivePeriod) * time.Second,
		})
		if err != nil {
			return nil, fmt.Errorf("listen on quic udp address %s error: %v", address, err)
		}

		log.Infof("frps quic listen on %s", address)

	}

	if cfg.SSHTunnelGateway.BindPort > 0 {

		// The gateway opens a port of its own, so it needs the rate limit in

		// its own hands: connections there never pass through HandleListener.

		var allowSSH ssh.AllowFunc

		if fw := svr.rc.Firewall; fw != nil {
			allowSSH = func(remoteAddr string) (bool, string) {
				if v := fw.AdmitSSH(remoteAddr); !v.Allowed {
					fw.NoteDecision(firewall.SurfaceSSH, false, v.Reason, remoteAddr)

					// An empty reason asks the gateway not to log this one: the
					// monitor's own reporter covers it, and under a flood a line
					// per rejection is a second flood.

					return false, ""
				}

				fw.NoteDecision(firewall.SurfaceSSH, true, "rate ok", remoteAddr)

				return true, "rate ok"
			}
		}

		sshGateway, err := ssh.NewGateway(cfg.SSHTunnelGateway, cfg.BindAddr, svr.sshTunnelListener, allowSSH)
		if err != nil {
			return nil, fmt.Errorf("create ssh gateway error: %v", err)
		}

		// Read per connection, so a change made through the dashboard reaches

		// the next peer rather than the next restart.

		if fw := svr.rc.Firewall; fw != nil {
			sshGateway.SetHandshakeByteLimit(fw.HandshakeByteLimit)
		}

		svr.sshTunnelGateway = sshGateway

		log.Infof("frps sshTunnelGateway listen on port %d", cfg.SSHTunnelGateway.BindPort)

	}

	// Listen for accepting connections from client using websocket protocol.

	websocketPrefix := []byte("GET " + netpkg.FrpWebsocketPath)

	websocketLn := svr.muxer.Listen(0, uint32(len(websocketPrefix)), func(data []byte) bool {
		return bytes.Equal(data, websocketPrefix)
	})

	svr.websocketListener = netpkg.NewWebsocketListener(websocketLn)

	// Create http vhost muxer.

	if cfg.VhostHTTPPort > 0 {

		rp := vhost.NewHTTPReverseProxy(vhost.HTTPReverseProxyOptions{
			ResponseHeaderTimeoutS: cfg.VhostHTTPTimeout,
		}, svr.httpVhostRouter)

		svr.rc.HTTPReverseProxy = rp

		address := net.JoinHostPort(cfg.ProxyBindAddr, strconv.Itoa(cfg.VhostHTTPPort))
		protocols := new(http.Protocols)
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		server := &http.Server{
			Addr: address,

			Handler: rp,

			ReadHeaderTimeout: 60 * time.Second,
			Protocols:         protocols,
		}

		var l net.Listener

		if httpMuxOn {
			l = svr.muxer.ListenHTTP(1)
		} else {

			l, err = net.Listen("tcp", address)
			if err != nil {
				return nil, fmt.Errorf("create vhost http listener error, %v", err)
			}

		}

		go func() {
			_ = server.Serve(l)
		}()

		log.Infof("http service listen on %s", address)

	}

	// Create https vhost muxer.

	if cfg.VhostHTTPSPort > 0 {

		var l net.Listener

		if httpsMuxOn {
			l = svr.muxer.ListenHTTPS(1)
		} else {

			address := net.JoinHostPort(cfg.ProxyBindAddr, strconv.Itoa(cfg.VhostHTTPSPort))

			l, err = net.Listen("tcp", address)
			if err != nil {
				return nil, fmt.Errorf("create server listener error, %v", err)
			}

			log.Infof("https service listen on %s", address)

		}

		svr.rc.VhostHTTPSMuxer, err = vhost.NewHTTPSMuxer(l, vhostReadWriteTimeout)
		if err != nil {
			return nil, fmt.Errorf("create vhost httpsMuxer error, %v", err)
		}

		// Init HTTPS group controller after HTTPSMuxer is created

		svr.rc.HTTPSGroupCtl = group.NewHTTPSGroupController(svr.rc.VhostHTTPSMuxer)

	}

	// frp tls listener

	svr.tlsListener = svr.muxer.Listen(2, 1, func(data []byte) bool {
		// tls first byte can be 0x16 only when vhost https port is not same with bind port

		return int(data[0]) == netpkg.FRPTLSHeadByte || int(data[0]) == 0x16
	})

	// The other half of the split made above the multiplexer. These three are
	// what it sorts client control traffic into, so this is the first point on
	// a shared port where the control rate limit can be applied to clients
	// without also applying it to a tunneled site's visitors.

	if sharedWithVhost && svr.rc.Firewall != nil {

		svr.listener = svr.rc.Firewall.GuardControl(svr.listener)

		svr.websocketListener = svr.rc.Firewall.GuardControl(svr.websocketListener)

		svr.tlsListener = svr.rc.Firewall.GuardControl(svr.tlsListener)

	}

	// Create nat hole controller.

	nc, err := nathole.NewController(time.Duration(cfg.NatHoleAnalysisDataReserveHours) * time.Hour)
	if err != nil {
		return nil, fmt.Errorf("create nat hole controller error, %v", err)
	}

	svr.rc.NatHoleController = nc

	return svr, nil
}

func (svr *Service) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)

	svr.ctx = ctx

	svr.cancel = cancel

	// run dashboard web server.

	if svr.webServer != nil {
		go func() {
			log.Infof("dashboard listen on %s", svr.webServer.Address())

			if err := svr.webServer.Run(); err != nil {
				log.Warnf("dashboard server exit with error: %v", err)
			}
		}()
	}

	go svr.HandleListener(svr.sshTunnelListener, true)

	if svr.kcpListener != nil {
		go svr.HandleListener(svr.kcpListener, false)
	}

	if svr.quicListener != nil {
		go svr.HandleQUICListener(svr.quicListener)
	}

	go svr.HandleListener(svr.websocketListener, false)

	go svr.HandleListener(svr.tlsListener, false)

	if svr.rc.NatHoleController != nil {
		go svr.rc.NatHoleController.CleanWorker(svr.ctx)
	}

	if svr.sshTunnelGateway != nil {
		go svr.sshTunnelGateway.Run()
	}

	svr.HandleListener(svr.listener, false)

	<-svr.ctx.Done()

	// service context may not be canceled by svr.Close(), we should call it here to release resources

	if svr.listener != nil {
		svr.Close()
	}
}

func (svr *Service) Close() error {
	if svr.kcpListener != nil {
		svr.kcpListener.Close()
	}

	if svr.quicListener != nil {
		svr.quicListener.Close()
	}

	if svr.websocketListener != nil {
		svr.websocketListener.Close()
	}

	if svr.tlsListener != nil {
		svr.tlsListener.Close()
	}

	if svr.sshTunnelListener != nil {
		svr.sshTunnelListener.Close()
	}

	if svr.listener != nil {
		svr.listener.Close()
	}

	if svr.webServer != nil {
		svr.webServer.Close()
	}

	if svr.sshTunnelGateway != nil {
		svr.sshTunnelGateway.Close()
	}

	// Takes frps back out of the host firewall, if it ever put itself in.
	// Addresses left in a kernel set would outlive the bans that put them
	// there, blocked with nothing left running to explain why.

	if svr.rc.Firewall != nil {
		svr.rc.Firewall.CloseKernelBan()
	}

	svr.rc.Close()

	svr.muxer.Close()

	svr.ctlManager.Close()

	if svr.cancel != nil {
		svr.cancel()
	}

	return nil
}

func (svr *Service) handleConnection(ctx context.Context, conn net.Conn, internal bool) {
	xl := xlog.FromContextSafe(ctx)

	// Reading the login is the last step before frps knows who this is, and it
	// is the only one the quic listener has - quic did its own tls, so nothing
	// upstream of here capped it. Capping it here covers every transport that
	// speaks frp: tcp, kcp, websocket, tls and quic alike.

	doneHandshake := func() {}

	if svr.rc.Firewall != nil {
		conn, doneHandshake = netpkg.LimitHandshake(conn, svr.rc.Firewall.HandshakeByteLimit())
	}

	acceptedConn, err := svr.acceptConnection(ctx, conn)

	// Lifted before anything is served, for the reason it is everywhere else:
	// the tunnel's bytes are not the handshake's.

	doneHandshake()

	if err != nil {

		// Anything that reaches the bind port but is not a frp client lands

		// here: port scanners, health checks, a misconfigured frpc. Worth a

		// warning with the address, so it can be answered with a firewall rule

		// - that is the only thing that makes the line actionable.

		log.Warnf("client conn [%s] was not a valid frp connection: %v", conn.RemoteAddr(), err)

		conn.Close()

		return

	}

	conn = acceptedConn.conn

	switch m := acceptedConn.firstMsg.(type) {

	case *msg.Login:

		// server plugin hook

		content := &plugin.LoginContent{
			Login: *m,

			ClientAddress: conn.RemoteAddr().String(),
		}

		retContent, err := svr.pluginManager.Login(content)

		var ctl *Control

		if err == nil {

			m = &retContent.Login

			controlConn := acceptedConn.conn

			if !internal {

				var controlRW io.ReadWriter

				controlRW, err = acceptedConn.newControlReadWriter(conn, svr.auth.EncryptionKey())

				if err == nil {
					controlConn = acceptedConn.messageConnFor(controlRW)
				}

			}

			if err == nil {
				ctl, err = svr.RegisterControl(controlConn, m, internal, acceptedConn.wireProtocol)
			}

		}

		if err != nil {
			xl.Warnf("register control error: %v", err)
			if ctl != nil {
				svr.ctlManager.Remove(ctl)
			}
			if writeErr := writeWithDeadline(conn, connWriteTimeout, func() error {
				return acceptedConn.conn.WriteMsg(&msg.LoginResp{
					Version: version.Full(),

					Error: util.GenerateResponseErrorString("register control error", err, lo.FromPtr(svr.cfg.DetailedErrorsToClient)),
				})
			}); writeErr != nil {
				xl.Warnf("client conn [%s] write login error response error: %v", conn.RemoteAddr(), writeErr)
			}
			if ctl != nil {
				_ = ctl.Close()
			} else {
				conn.Close()
			}
			return

		}
		if err = svr.completeControlLogin(ctl, func() error {
			return writeWithDeadline(conn, connWriteTimeout, func() error {
				return acceptedConn.conn.WriteMsg(&msg.LoginResp{
					Version: version.Full(),
					RunID:   ctl.runID,
					Error:   "",
				})
			})
		}); err != nil {
			xl.Warnf("complete control login error: %v", err)
			svr.ctlManager.Remove(ctl)
			_ = ctl.Close()
			return

		}
	case *msg.NewWorkConn:

		if err := svr.RegisterWorkConn(acceptedConn.conn, m); err != nil {

			_ = acceptedConn.conn.WriteMsg(&msg.StartWorkConn{
				Error: util.GenerateResponseErrorString("invalid NewWorkConn", err, lo.FromPtr(svr.cfg.DetailedErrorsToClient)),
			})

			conn.Close()

		}

	case *msg.NewVisitorConn:

		if err = svr.RegisterVisitorConn(conn, m, acceptedConn.wireProtocol); err != nil {

			xl.Warnf("client conn [%s] register visitor conn error: %v", conn.RemoteAddr(), err)

			_ = acceptedConn.conn.WriteMsg(&msg.NewVisitorConnResp{
				ProxyName: m.ProxyName,

				Error: util.GenerateResponseErrorString("register visitor conn error", err, lo.FromPtr(svr.cfg.DetailedErrorsToClient)),
			})

			conn.Close()

		} else {
			_ = acceptedConn.conn.WriteMsg(&msg.NewVisitorConnResp{
				ProxyName: m.ProxyName,

				Error: "",
			})
		}

	default:

		log.Warnf("error message type for the new connection [%s]", conn.RemoteAddr().String())

		conn.Close()

	}
}

func (svr *Service) completeControlLogin(ctl *Control, writeSuccess func() error) error {
	committed, err := svr.ctlManager.completeLogin(ctl, writeSuccess)
	if err != nil {
		return err
	}
	if !committed {
		return errControlReplaced
	}
	return nil
}

type acceptedConnection struct {
	conn *msg.Conn

	wireProtocol string

	cryptoContext *wire.CryptoContext

	firstMsg msg.Message
}

func (svr *Service) acceptConnection(ctx context.Context, conn net.Conn) (*acceptedConnection, error) {
	_ = conn.SetReadDeadline(time.Now().Add(connReadTimeout))

	checkedConn, isV2, err := wire.CheckMagic(conn)
	if err != nil {
		return nil, fmt.Errorf("read wire protocol magic: %w", err)
	}

	wireProtocol := wire.ProtocolV1

	if isV2 {
		wireProtocol = wire.ProtocolV2
	}

	conn = netpkg.NewContextConn(ctx, checkedConn)

	acceptedConn := &acceptedConnection{wireProtocol: wireProtocol}

	if isV2 {

		wireConn := wire.NewConn(conn)

		rw := msg.NewV2ReadWriterWithConn(wireConn)

		acceptedConn.conn = msg.NewConn(conn, rw)

		acceptedConn.firstMsg, err = acceptedConn.readFirstV2Msg(conn, wireConn)

	} else {

		rw := msg.NewV1ReadWriter(conn)

		acceptedConn.conn = msg.NewConn(conn, rw)

		acceptedConn.firstMsg, err = acceptedConn.conn.ReadMsg()

	}

	if err != nil {
		return nil, err
	}

	_ = conn.SetReadDeadline(time.Time{})

	return acceptedConn, nil
}

func writeWithDeadline(conn net.Conn, timeout time.Duration, writeFn func() error) error {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))

	defer func() {
		_ = conn.SetWriteDeadline(time.Time{})
	}()

	return writeFn()
}

func (ac *acceptedConnection) messageConnFor(rw io.ReadWriter) *msg.Conn {
	return msg.NewConn(ac.conn, msg.NewReadWriter(rw, ac.wireProtocol))
}

func (ac *acceptedConnection) newControlReadWriter(rw io.ReadWriter, key []byte) (io.ReadWriter, error) {
	if ac.wireProtocol == wire.ProtocolV2 {

		if ac.cryptoContext == nil {
			return nil, fmt.Errorf("missing v2 crypto negotiation")
		}

		return netpkg.NewAEADCryptoReadWriter(

			rw,

			key,

			netpkg.AEADCryptoRoleServer,

			ac.cryptoContext.Algorithm,

			ac.cryptoContext.TranscriptHash,
		)

	}

	return netpkg.NewCryptoReadWriter(rw, key)
}

func (ac *acceptedConnection) readFirstV2Msg(conn net.Conn, wireConn *wire.Conn) (msg.Message, error) {
	frame, err := wireConn.ReadFrame()
	if err != nil {
		return nil, fmt.Errorf("read v2 frame: %w", err)
	}

	if frame.Type == wire.FrameTypeClientHello {

		if err := ac.handleClientHello(conn, wireConn, frame); err != nil {
			return nil, err
		}

		frame, err = wireConn.ReadFrame()
		if err != nil {
			return nil, fmt.Errorf("read first v2 message frame: %w", err)
		}

	}

	m, err := msg.DecodeV2MessageFrame(frame)
	if err != nil {
		return nil, fmt.Errorf("decode v2 message: %w", err)
	}

	return m, nil
}

func (ac *acceptedConnection) handleClientHello(conn net.Conn, wireConn *wire.Conn, frame *wire.Frame) error {
	var hello wire.ClientHello

	if err := wireConn.UnmarshalFrame(frame, &hello); err != nil {
		return fmt.Errorf("decode ClientHello: %w", err)
	}

	serverHello, err := wire.NewServerHello(hello)
	if err != nil {

		serverHello = wire.DefaultServerHello()

		serverHello.Error = err.Error()

		if writeErr := writeWithDeadline(conn, connWriteTimeout, func() error {
			return wireConn.WriteJSONFrame(wire.FrameTypeServerHello, serverHello)
		}); writeErr != nil {
			return fmt.Errorf("%w; write ServerHello error: %v", err, writeErr)
		}

		return err

	}

	serverHelloFrame, err := wire.NewJSONFrame(wire.FrameTypeServerHello, serverHello)
	if err != nil {
		return fmt.Errorf("encode ServerHello: %w", err)
	}

	cryptoContext := wire.NewCryptoContext(

		serverHello.Selected.Crypto.Algorithm,

		frame.Payload,

		serverHelloFrame.Payload,
	)

	if err := writeWithDeadline(conn, connWriteTimeout, func() error {
		return wireConn.WriteFrame(serverHelloFrame)
	}); err != nil {
		return fmt.Errorf("write ServerHello: %w", err)
	}

	ac.cryptoContext = cryptoContext

	return nil
}

// localPort is the port a connection landed on, which is what a firewall rule

// names. Returns 0 when the address carries no port.

func localPort(addr net.Addr) int {
	if addr == nil {
		return 0
	}

	switch a := addr.(type) {

	case *net.TCPAddr:

		return a.Port

	case *net.UDPAddr:

		return a.Port

	}

	_, port, err := net.SplitHostPort(addr.String())
	if err != nil {
		return 0
	}

	n, err := strconv.Atoi(port)
	if err != nil {
		return 0
	}

	return n
}

// HandleListener accepts connections from client and call handleConnection to handle them.

// If internal is true, it means that this listener is used for internal communication like ssh tunnel gateway.

// TODO(fatedier): Pass some parameters of listener/connection through context to avoid passing too many parameters.

// maxPendingHandshakes bounds how many connections may be in the middle of the
// TLS sniff at once.
//
// The sniff is a read that waits for the peer to say something. Running it in
// the accept loop, which is what used to happen, meant a single silent peer
// held up every other client for the whole read timeout. Handling it
// concurrently fixes that; a bound is what stops the fix from being its own
// problem, because a flood would otherwise become one goroutine per connection.
//
// The firewall is not part of this stage any more - it runs on the raw
// listener, before the multiplexer, so most of a flood never reaches here.
//
// At the limit new connections are refused outright. Turning somebody away
// quickly is a better answer than queueing them behind work that is already not
// keeping up.
const maxPendingHandshakes = 2048

func (svr *Service) HandleListener(l net.Listener, internal bool) {
	// Listen for incoming connections from client.

	pending := make(chan struct{}, maxPendingHandshakes)

	for {

		c, err := l.Accept()
		if err != nil {

			log.Warnf("listener for incoming connections from client closed")

			return

		}

		select {

		case pending <- struct{}{}:

		default:

			// Every admission slot is busy. Refuse rather than wait: the accept
			// loop staying responsive is the whole point of the bound.

			netpkg.ArmReset(c)

			c.Close()

			continue

		}

		go func(c net.Conn) {
			// Released once admission is over, not when serving is: a tunnel
			// stays up for hours and must not hold a slot meant for the few
			// hundred milliseconds of deciding whether to let it in. OnceFunc
			// so the deferred safety net cannot free a slot twice when the
			// explicit release has already run.

			release := sync.OnceFunc(func() { <-pending })

			defer release()

			svr.admitAndServe(c, internal, release)
		}(c)

	}
}

// admitAndServe runs the checks that may block, then hands the connection on.
// Called on its own goroutine - see maxPendingHandshakes for why.
func (svr *Service) admitAndServe(c net.Conn, internal bool, release func()) {
	// No firewall check here. Every listener that carries real remote peers is
	// wrapped by firewall.GuardControl at the point it is created, which is
	// upstream of the protocol multiplexer and so upstream of this. Checking
	// again would count one connection twice against the rate limit and halve
	// every configured limit.

	// inject xlog object into net.Conn context

	xl := xlog.New()

	ctx := context.Background()

	c = netpkg.NewContextConn(xlog.NewContext(ctx, xl), c)

	if !internal {

		log.Tracef("start check TLS connection...")

		originConn := c

		forceTLS := svr.cfg.Transport.TLS.Force

		var (
			isTLS, custom bool

			err error
		)

		// Shortened while under attack: a peer that opens a connection and
		// says nothing holds a socket for the whole timeout, and that is
		// what a slow flood is made of.

		timeout := connReadTimeout

		// And bounded by size as well as by time. A peer that opens a
		// connection and then pushes megabytes without ever identifying itself
		// breaks no rate at all - one connection is one connection - but it
		// does spend the memory a pending handshake holds.

		doneHandshake := func() {}

		if svr.rc.Firewall != nil {
			timeout = svr.rc.Firewall.HandshakeTimeout(timeout)

			c, doneHandshake = netpkg.LimitHandshake(c, svr.rc.Firewall.HandshakeByteLimit())
		}

		c, isTLS, custom, err = netpkg.CheckAndEnableTLSServerConnWithTimeout(c, svr.tlsConfig, forceTLS, timeout)

		// Lifted as soon as the peer has identified itself, and not deferred:
		// serving runs to the end of this function, so a deferred lift would
		// leave the cap in force for the whole life of the tunnel.

		doneHandshake()

		if err != nil {

			log.Warnf("client conn [%s] failed the TLS check: %v", originConn.RemoteAddr(), err)

			// Not an frpc having a bad day: something that does not speak
			// the protocol at all. Worth more than any amount of counting,
			// so it goes straight to the strike ledger.

			if svr.rc.Firewall != nil {
				svr.rc.Firewall.ReportProtocolFailure(originConn.RemoteAddr().String())
			}

			netpkg.ArmReset(originConn)

			originConn.Close()

			return

		}

		log.Tracef("check TLS connection success, isTLS: %v custom: %v internal: %v", isTLS, custom, internal)

	}

	// Admission is over. Free the slot before serving, which may go on for
	// hours.

	release()

	func(ctx context.Context, frpConn net.Conn) {
		if lo.FromPtr(svr.cfg.Transport.TCPMux) && !internal {

			fmuxCfg := fmux.DefaultConfig()

			fmuxCfg.KeepAliveInterval = time.Duration(svr.cfg.Transport.TCPMuxKeepaliveInterval) * time.Second

			// Use trace level for yamux logs

			fmuxCfg.LogOutput = xlog.NewTraceWriter(xlog.FromContextSafe(ctx))

			fmuxCfg.MaxStreamWindowSize = 6 * 1024 * 1024

			session, err := fmux.Server(frpConn, fmuxCfg)
			if err != nil {

				log.Warnf("failed to create mux connection: %v", err)

				frpConn.Close()

				return

			}

			for {

				stream, err := session.AcceptStream()
				if err != nil {

					log.Debugf("accept new mux stream error: %v", err)

					session.Close()

					return

				}

				go svr.handleConnection(ctx, stream, internal)

			}

		} else {
			svr.handleConnection(ctx, frpConn, internal)
		}
	}(ctx, c)
}

func (svr *Service) HandleQUICListener(l *quic.Listener) {
	// Listen for incoming connections from client.

	for {

		c, err := l.Accept(context.Background())
		if err != nil {

			log.Warnf("quic listener for incoming connections from client closed")

			return

		}

		// Rate limit: turn a flooding client away before any stream is accepted.

		if fw := svr.rc.Firewall; fw != nil {

			remoteAddr := c.RemoteAddr().String()

			// The same reporting as the tcp listener, so a flood over quic is
			// not the one that goes unmentioned. No RST to arm here - quic
			// closes without leaving TIME_WAIT behind.

			if v := fw.AdmitControl(remoteAddr); !v.Allowed {

				fw.NoteDecision(firewall.SurfaceControl, false, v.Reason, remoteAddr)

				_ = c.CloseWithError(0, "")

				continue

			}

			fw.NoteDecision(firewall.SurfaceControl, true, "rate ok", remoteAddr)
		}

		// Start a new goroutine to handle connection.

		go func(ctx context.Context, frpConn *quic.Conn) {
			for {

				stream, err := frpConn.AcceptStream(context.Background())
				if err != nil {

					log.Debugf("accept new quic mux stream error: %v", err)

					_ = frpConn.CloseWithError(0, "")

					return

				}

				go svr.handleConnection(ctx, netpkg.QuicStreamToNetConn(stream, frpConn), false)

			}
		}(context.Background(), c)

	}
}

func (svr *Service) RegisterControl(
	ctlConn *msg.Conn,

	loginMsg *msg.Login,

	internal bool,

	wireProtocol string,
) (*Control, error) {
	// If client's RunID is empty, it's a new client, we just create a new controller.

	// Otherwise, we check if there is one controller has the same run id. If so, we release previous controller and start new one.

	var err error

	if loginMsg.RunID == "" {

		loginMsg.RunID, err = util.RandID()
		if err != nil {
			return nil, err
		}

	}

	ctx := netpkg.NewContextFromConn(ctlConn)

	xl := xlog.FromContextSafe(ctx)

	xl.AppendPrefix(loginMsg.RunID)

	ctx = xlog.NewContext(ctx, xl)

	xl.Infof("client login info: ip [%s] version [%s] hostname [%s] os [%s] arch [%s]",

		ctlConn.RemoteAddr().String(), loginMsg.Version, loginMsg.Hostname, loginMsg.Os, loginMsg.Arch)

	// Check auth.

	authVerifier := svr.auth.Verifier

	if internal && loginMsg.ClientSpec.AlwaysAuthPass {
		authVerifier = auth.AlwaysPassVerifier
	}

	if err := authVerifier.VerifyLogin(loginMsg); err != nil {

		// A wrong token is the same class of evidence as a wrong protocol: an
		// frpc that belongs here knows the secret. Internal connections - the
		// ssh gateway's own pipe - are exempt, having never been remote peers.

		if !internal && svr.rc.Firewall != nil && ctlConn != nil {
			svr.rc.Firewall.ReportProtocolFailure(ctlConn.RemoteAddr().String())
		}

		return nil, err

	}

	ctl, err := NewControl(ctx, &SessionContext{
		RC:            svr.rc,
		PxyManager:    svr.pxyManager,
		PluginManager: svr.pluginManager,
		AuthVerifier:  authVerifier,
		EncryptionKey: svr.auth.EncryptionKey(),
		Conn:          ctlConn,
		LoginMsg:      loginMsg,
		ServerCfg:     svr.cfg,
		WireProtocol:  wireProtocol,
	})
	if err != nil {

		xl.Warnf("create new controller error: %v", err)

		// don't return detailed errors to client

		return nil, fmt.Errorf("unexpected error when creating new controller")

	}

	if err := svr.ctlManager.Add(ctl); err != nil {
		return ctl, err
	}
	ctl.WaitForHandoff()

	active, err := svr.ctlManager.Activate(ctl)
	if err != nil {
		return ctl, err
	}
	if !active {
		return ctl, errControlReplaced
	}

	return ctl, nil
}

// RegisterWorkConn register a new work connection to control and proxies need it.

func (svr *Service) RegisterWorkConn(workConn *msg.Conn, newMsg *msg.NewWorkConn) error {
	xl := netpkg.NewLogFromConn(workConn)

	ctl, exist := svr.ctlManager.GetByID(newMsg.RunID)

	if !exist {

		xl.Warnf("client conn [%s] sent a work conn for unknown run id [%s]", workConn.RemoteAddr(), newMsg.RunID)

		return fmt.Errorf("no client control found for run id [%s]", newMsg.RunID)

	}

	// server plugin hook

	content := &plugin.NewWorkConnContent{
		User: plugin.UserInfo{
			User: ctl.sessionCtx.LoginMsg.User,

			Metas: ctl.sessionCtx.LoginMsg.Metas,

			RunID: ctl.sessionCtx.LoginMsg.RunID,
		},

		NewWorkConn: *newMsg,
	}

	retContent, err := svr.pluginManager.NewWorkConn(content)

	if err == nil {

		newMsg = &retContent.NewWorkConn

		// Check auth.

		err = ctl.sessionCtx.AuthVerifier.VerifyNewWorkConn(newMsg)

	}

	if err != nil {

		xl.Warnf("client conn [%s] sent an invalid work conn for run id [%s]", workConn.RemoteAddr(), newMsg.RunID)

		return err

	}
	return svr.ctlManager.RegisterWorkConn(ctl, proxy.NewWorkConn(workConn))
}

func (svr *Service) RegisterVisitorConn(visitorConn net.Conn, newMsg *msg.NewVisitorConn, wireProtocol string) error {
	admit := func(visitorUser string) error {
		return svr.rc.VisitorManager.NewConn(newMsg.ProxyName, visitorConn, newMsg.Timestamp, newMsg.SignKey,
			newMsg.UseEncryption, newMsg.UseCompression, visitorUser, wireProtocol)
	}
	// TODO(deprecation): Compatible with old versions, can be without runID, user is empty. In later versions, it will be mandatory to include runID.

	// If runID is required, it is not compatible with versions prior to v0.50.0.

	if newMsg.RunID != "" {
		admitted, err := svr.ctlManager.admitVisitorByRunID(newMsg.RunID, admit)
		if err != nil {
			return err
		}
		if !admitted {
			return fmt.Errorf("no client control found for run id [%s]", newMsg.RunID)
		}
		return nil
	}
	return admit("")
}
