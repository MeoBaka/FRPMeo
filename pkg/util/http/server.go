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

package http

import (
	"crypto/tls"
	stdlog "log"
	"net"
	"net/http"
	"net/http/pprof"
	"strconv"
	"time"

	"github.com/gorilla/mux"

	"github.com/fatedier/frp/assets"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/util/guard"
	"github.com/fatedier/frp/pkg/util/log"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

var (
	defaultReadTimeout = 60 * time.Second

	defaultWriteTimeout = 60 * time.Second
)

type Server struct {
	addr string

	ln net.Listener

	tlsCfg *tls.Config

	router *mux.Router

	hs *http.Server

	authMiddleware mux.MiddlewareFunc

	// connFilter, when set, decides which peers get as far as the handshake.

	// See SetConnFilter.

	connFilter func(remoteAddr string) bool

	// auth is kept so the failure hook can be attached after construction.

	auth *netpkg.HTTPAuthMiddleware

	// guard is the allow list and the failed-login ban, nil when the config

	// asked for neither. It runs ahead of connFilter: being on the list is a

	// question about who the peer is, and there is no point asking anything

	// else of somebody who is not.

	guard *guard.Guard
}

func NewServer(cfg v1.WebServerConfig) (*Server, error) {
	assets.Load(cfg.AssetsDir)

	addr := net.JoinHostPort(cfg.Addr, strconv.Itoa(cfg.Port))

	if addr == ":" {
		addr = ":http"
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	router := mux.NewRouter()

	hs := &http.Server{
		Addr: addr,

		Handler: router,

		ReadTimeout: defaultReadTimeout,

		WriteTimeout: defaultWriteTimeout,

		// Anything reaching an exposed port draws scanners, and a failed TLS

		// handshake is one line each: a probe speaking plain HTTP to a TLS

		// port, a connection hung up halfway through. Left unset, net/http

		// writes them with the standard logger straight to stderr, where the

		// configured level cannot quiet them and the log file cannot hold

		// them. Debug keeps them reachable without letting them drown a log.

		ErrorLog: stdlog.New(log.NewWriteLogger(log.DebugLevel, 2), "", 0),
	}

	s := &Server{
		addr: addr,

		ln: ln,

		hs: hs,

		router: router,
	}

	if cfg.PprofEnable {
		s.registerPprofHandlers()
	}

	if cfg.TLS != nil {

		cert, err := tls.LoadX509KeyPair(cfg.TLS.CertFile, cfg.TLS.KeyFile)
		if err != nil {
			return nil, err
		}

		s.tlsCfg = &tls.Config{
			Certificates: []tls.Certificate{cert},
		}

	}

	s.guard, err = guard.New(guard.Config{
		AllowCIDRs: cfg.AllowCIDRs,

		MaxLoginFailures: cfg.MaxLoginFailures,

		BanSeconds: cfg.LoginBanSeconds,
	})
	if err != nil {

		_ = ln.Close()

		return nil, err

	}

	s.auth = netpkg.NewHTTPAuthMiddleware(cfg.User, cfg.Password).SetAuthFailDelay(200 * time.Millisecond)

	// The guard counts failures itself. Anyone calling SetOnAuthFail is added

	// alongside rather than in place of it, so wiring an observer cannot

	// silently disarm the ban.

	s.auth.SetOnAuthFail(s.guard.ReportLoginFailure)

	s.authMiddleware = s.auth.Middleware

	return s, nil
}

// SetOnAuthFail installs a callback run for every rejected login on this
// server, with the address it came from.

//

// Separate from SetConnFilter because it answers a different question: the
// filter decides whether a peer may reach the handshake at all, this reports
// what the peer turned out to be once it got there. A wrong password is the
// clearest evidence this port produces - nobody who belongs here gets it wrong
// again and again - so it is worth acting on with far less patience than a
// rate.

//

// Must be called before Run.

func (s *Server) SetOnAuthFail(fn func(remoteAddr string)) {
	if s.auth == nil || fn == nil {
		return
	}
	g := s.guard

	s.auth.SetOnAuthFail(func(remoteAddr string) {
		g.ReportLoginFailure(remoteAddr)

		fn(remoteAddr)
	})
}

func (s *Server) Address() string {
	return s.addr
}

// SetHandshakeByteLimit caps how much a peer may send before it has finished
// asking for something - the request line and headers, and the TLS handshake
// underneath them when the dashboard serves https.
//
// The same measurement the control port makes, in the form net/http already
// offers. A peer that opens a connection and pushes megabytes of headers costs
// the memory a pending request holds while breaking no rate at all: one
// connection is one connection however much it carries.
//
// Zero leaves net/http's own default in place. Must be called before Run.
func (s *Server) SetHandshakeByteLimit(n int) {
	if n <= 0 {
		return
	}
	s.hs.MaxHeaderBytes = n
}

// SetConnFilter installs a check run on every accepted connection. It is asked

// before the TLS handshake and before a single byte is read, so a peer it turns

// away costs nothing beyond the accept itself - which is also why it is the

// only place a rejection can stop the handshake noise rather than add to it.

//

// It reports only whether to admit the peer: what to say about a rejection, and

// how loudly, belongs to whoever knows why the answer was no.

//

// Must be called before Run.

func (s *Server) SetConnFilter(allow func(remoteAddr string) bool) {
	s.connFilter = allow
}

func (s *Server) Run() error {
	ln := s.ln

	// Before the TLS wrapper, not after: a connection turned away here must not

	// have been handed to a handshake first.

	if s.guard != nil || s.connFilter != nil {
		ln = &filteredListener{Listener: ln, guard: s.guard, allow: s.connFilter}
	}

	if s.tlsCfg != nil {
		ln = tls.NewListener(ln, s.tlsCfg)
	}

	return s.hs.Serve(ln)
}

// filteredListener drops connections the filter refuses, so the server above it

// never learns they arrived.

type filteredListener struct {
	net.Listener

	guard *guard.Guard

	allow func(remoteAddr string) bool
}

func (l *filteredListener) Accept() (net.Conn, error) {
	for {

		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}

		addr := c.RemoteAddr().String()

		if l.guard.Allow(addr) && (l.allow == nil || l.allow(addr)) {
			return c, nil
		}

		// RST rather than a graceful close. A peer that is being turned away
		// has no use for an orderly shutdown, and a graceful close leaves this
		// side holding a TIME_WAIT socket for two minutes per rejection -
		// which is the wrong way round when the rejections are a flood.

		netpkg.ArmReset(c)

		_ = c.Close()

	}
}

func (s *Server) Close() error {
	err := s.hs.Close()

	if s.ln != nil {
		_ = s.ln.Close()
	}

	return err
}

type RouterRegisterHelper struct {
	Router *mux.Router

	AssetsFS http.FileSystem

	AuthMiddleware mux.MiddlewareFunc
}

func (s *Server) RouteRegister(register func(helper *RouterRegisterHelper)) {
	register(&RouterRegisterHelper{
		Router: s.router,

		AssetsFS: assets.FileSystem,

		AuthMiddleware: s.authMiddleware,
	})
}

func (s *Server) registerPprofHandlers() {
	s.router.HandleFunc("/debug/pprof/cmdline", pprof.Cmdline)

	s.router.HandleFunc("/debug/pprof/profile", pprof.Profile)

	s.router.HandleFunc("/debug/pprof/symbol", pprof.Symbol)

	s.router.HandleFunc("/debug/pprof/trace", pprof.Trace)

	s.router.PathPrefix("/debug/pprof/").HandlerFunc(pprof.Index)
}
