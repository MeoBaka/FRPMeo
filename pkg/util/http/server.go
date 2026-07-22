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
	"github.com/fatedier/frp/pkg/util/log"
	netpkg "github.com/fatedier/frp/pkg/util/net"
)

var (
	defaultReadTimeout  = 60 * time.Second
	defaultWriteTimeout = 60 * time.Second
)

type Server struct {
	addr   string
	ln     net.Listener
	tlsCfg *tls.Config

	router *mux.Router
	hs     *http.Server

	authMiddleware mux.MiddlewareFunc

	// connFilter, when set, decides which peers get as far as the handshake.
	// See SetConnFilter.
	connFilter func(remoteAddr string) bool
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
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  defaultReadTimeout,
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
		addr:   addr,
		ln:     ln,
		hs:     hs,
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
	s.authMiddleware = netpkg.NewHTTPAuthMiddleware(cfg.User, cfg.Password).SetAuthFailDelay(200 * time.Millisecond).Middleware
	return s, nil
}

func (s *Server) Address() string {
	return s.addr
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
	if s.connFilter != nil {
		ln = &filteredListener{Listener: ln, allow: s.connFilter}
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
	allow func(remoteAddr string) bool
}

func (l *filteredListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if l.allow(c.RemoteAddr().String()) {
			return c, nil
		}
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
	Router         *mux.Router
	AssetsFS       http.FileSystem
	AuthMiddleware mux.MiddlewareFunc
}

func (s *Server) RouteRegister(register func(helper *RouterRegisterHelper)) {
	register(&RouterRegisterHelper{
		Router:         s.router,
		AssetsFS:       assets.FileSystem,
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
