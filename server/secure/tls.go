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

package secure

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/fatedier/frp/pkg/util/log"
)

// Signing in over TLS, on a tcp proxy whose backend speaks it - a web server,
// or frpc's https2http plugin. That TLS is the backend's to open, not frps',
// so a visitor who typed https:// could only ever be reset. frps answers them
// over TLS of its own instead, with a certificate it makes for the purpose:
// the browser warns about it once, the visitor signs in, and is sent back to
// the page, which from then on goes straight through to the backend.

// knockCertFile is where frps keeps that certificate, next to where it runs.
// Kept rather than made anew at every start: a browser told to accept it once
// goes on accepting it across restarts.
var knockCertFile = ".autogen_secure_tls.pem"

const (
	// knockCertLifetime stays within the validity browsers accept at all.
	knockCertLifetime = 397 * 24 * time.Hour

	// knockCertRenewBefore replaces the certificate this long before it runs
	// out.
	knockCertRenewBefore = 30 * 24 * time.Hour
)

var (
	knockTLSMu       sync.Mutex
	knockTLSCfg      *tls.Config
	knockTLSNotAfter time.Time
)

// looksLikeTLS reports whether the connection opens with a TLS handshake
// record. Only a first byte that could start one is waited on for the rest of
// the record header, so anything else is still refused at once.
func looksLikeTLS(br *bufio.Reader) bool {
	if first, err := br.Peek(1); err != nil || first[0] != 0x16 {
		return false
	}
	head, err := br.Peek(3)
	return err == nil && head[1] == 0x03 && head[2] <= 0x04
}

// answerTLSKnock serves one unlock request that arrived over TLS, answering a
// good key with a redirect back to the page asked for.
func (g *Gate) answerTLSKnock(c net.Conn, br *bufio.Reader, ip netip.Addr) {
	cfg, err := knockTLSConfig()
	if err != nil {
		log.Debugf("secure: no certificate to answer a TLS sign-in with: %v", err)
		return
	}
	_ = c.SetDeadline(time.Now().Add(knockTimeout))
	tc := tls.Server(&replayConn{Conn: c, r: br}, cfg)
	if err := tc.Handshake(); err != nil {
		return
	}
	req, err := http.ReadRequest(bufio.NewReader(io.LimitReader(tc, maxKnockRequest)))
	if err != nil {
		return
	}
	req.RemoteAddr = c.RemoteAddr().String()
	state := tc.ConnectionState()
	req.TLS = &state
	_ = g.knock(req, ip, redirectBack).write(tc, req)
	_ = tc.CloseWrite()
}

// knockTLSConfig is the TLS sign-ins are answered with. Made on first use, so
// an frps whose secure proxies never see TLS never writes a certificate, and
// remade when the certificate is close to running out.
func knockTLSConfig() (*tls.Config, error) {
	knockTLSMu.Lock()
	defer knockTLSMu.Unlock()

	if knockTLSCfg != nil && time.Now().Before(knockTLSNotAfter.Add(-knockCertRenewBefore)) {
		return knockTLSCfg, nil
	}
	cert, err := loadKnockCert(knockCertFile)
	if err != nil {
		var pemData []byte
		if cert, pemData, err = newKnockCert(time.Now().Add(knockCertLifetime)); err != nil {
			return nil, err
		}
		if err := os.WriteFile(knockCertFile, pemData, 0o600); err != nil {
			// It still works for as long as frps runs; browsers just get
			// asked again after a restart.
			log.Warnf("secure: keep the TLS sign-in certificate in %s: %v", knockCertFile, err)
		}
	}
	knockTLSCfg = &tls.Config{
		Certificates: []tls.Certificate{cert},
		// What is read from the connection is HTTP/1.1, so that is all that is
		// offered.
		NextProtos: []string{"http/1.1"},
		// The visitor's next connection goes to the backend, which could not
		// resume a session frps issued.
		SessionTicketsDisabled: true,
		MinVersion:             tls.VersionTLS12,
	}
	knockTLSNotAfter = cert.Leaf.NotAfter
	return knockTLSCfg, nil
}

// loadKnockCert reads a kept certificate, refusing one close to running out.
func loadKnockCert(path string) (tls.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, err
	}
	cert, err := tls.X509KeyPair(data, data)
	if err != nil {
		return tls.Certificate{}, err
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0]); err != nil {
			return tls.Certificate{}, err
		}
	}
	if !time.Now().Before(cert.Leaf.NotAfter.Add(-knockCertRenewBefore)) {
		return tls.Certificate{}, os.ErrNotExist
	}
	return cert, nil
}

// newKnockCert makes a self-signed certificate for this host's own addresses,
// good until notAfter, and returns it with its PEM form to keep.
func newKnockCert(notAfter time.Time) (tls.Certificate, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "frp secure access"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// Visitors mostly reach a tcp proxy by the server's address, so the
		// certificate names the addresses this host has. It is not trusted
		// either way; naming the right one spares one more warning.
		DNSNames:    []string{"localhost"},
		IPAddresses: hostIPs(),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pemData := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	pemData = append(pemData, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})...)
	cert, err := tls.X509KeyPair(pemData, pemData)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	if cert.Leaf == nil {
		if cert.Leaf, err = x509.ParseCertificate(der); err != nil {
			return tls.Certificate{}, nil, err
		}
	}
	return cert, pemData, nil
}

// hostIPs is every address of this host, loopback included.
func hostIPs() []net.IP {
	ips := []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ips
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && !n.IP.IsLoopback() && !n.IP.IsLinkLocalUnicast() {
			ips = append(ips, n.IP)
		}
	}
	return ips
}
