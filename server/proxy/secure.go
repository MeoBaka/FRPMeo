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
	"errors"
	"fmt"
	"net"
	"strconv"
)

// errSecureNoHTTPPort is returned for a secure https proxy that could only be
// unlocked through frps' http port, when frps has none.
var errSecureNoHTTPPort = errors.New("secure: https proxies take unlock links on frps' http port - set vhostHTTPPort on frps, or add trustedIPs")

// newUDPPacketFilter is newUDPAdmitFilter plus secure access, which has to see
// each datagram rather than its size: an unlock can arrive as one.
func (pxy *BaseProxy) newUDPPacketFilter(port int) func(string, []byte) bool {
	admit := pxy.newUDPAdmitFilter(port)
	gate := pxy.gate
	switch {
	case gate == nil && admit == nil:
		return nil
	case gate == nil:
		return func(remoteAddr string, packet []byte) bool {
			return admit(remoteAddr, len(packet))
		}
	}
	return func(remoteAddr string, packet []byte) bool {
		if admit != nil && !admit(remoteAddr, len(packet)) {
			return false
		}
		return gate.AdmitPacket(remoteAddr, packet)
	}
}

// listenForSecureKnocks opens the tcp listener a udp or pe proxy takes unlock
// links on - a datagram cannot carry one - and returns the port it holds, or 0.
// Not getting the port is only fatal when nothing else could let a visitor in.
func (pxy *BaseProxy) listenForSecureKnocks(port int) (int, error) {
	gate := pxy.gate
	if gate == nil || !gate.TakesRequests() {
		return 0, nil
	}
	fail := func(err error) (int, error) {
		if gate.HasOtherWayIn() {
			pxy.xl.Warnf("secure: unlock links unavailable on tcp port %d: %v", port, err)
			return 0, nil
		}
		return 0, fmt.Errorf("secure: unlock links need tcp port %d: %v", port, err)
	}
	// Through the port manager, so allowPorts holds and no tcp proxy is handed
	// the port later.
	if _, err := pxy.rc.TCPPortManager.Acquire(pxy.name, port); err != nil {
		return fail(err)
	}
	l, err := net.Listen("tcp", net.JoinHostPort(pxy.serverCfg.ProxyBindAddr, strconv.Itoa(port)))
	if err != nil {
		pxy.rc.TCPPortManager.Release(port)
		return fail(err)
	}
	pxy.listeners = append(pxy.listeners, l)
	go gate.ServeKnocks(l)
	pxy.xl.Infof("secure: unlock links on tcp port %d", port)
	return port, nil
}

// registerSecureKnocks lets unlock requests for domains reach the proxy's gate
// through frps' http port. TLS passes through frps untouched, so that is the
// only place an https proxy can take a key.
func (pxy *HTTPSProxy) registerSecureKnocks(domains []string) error {
	gate := pxy.gate
	if gate == nil {
		return nil
	}
	if pxy.rc.HTTPReverseProxy == nil || pxy.rc.SecureKnocks == nil {
		if gate.HasOtherWayIn() {
			pxy.xl.Warnf("secure: frps has no http port for unlock links, so only trustedIPs can reach this proxy")
			return nil
		}
		return errSecureNoHTTPPort
	}
	for _, d := range domains {
		pxy.rc.SecureKnocks.Register(d, gate)
	}
	pxy.knockDomains = domains
	return nil
}

func (pxy *HTTPSProxy) unregisterSecureKnocks() {
	for _, d := range pxy.knockDomains {
		pxy.rc.SecureKnocks.Unregister(d, pxy.gate)
	}
	pxy.knockDomains = nil
}
