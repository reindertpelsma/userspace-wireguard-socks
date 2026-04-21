// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
)

// transportCA issues server and client certificates for transport integration tests.
type transportCA struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	caFile string
	dir    string
}

func newTransportCA(t *testing.T) *transportCA {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "transport-test-ca"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	caFile := dir + "/ca.crt"
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &transportCA{cert: cert, key: priv, caFile: caFile, dir: dir}
}

func (ca *transportCA) issueServer(t *testing.T, name string, ipAddrs []net.IP) (certFile, keyFile string) {
	t.Helper()
	return ca.issue(t, name, nil, ipAddrs, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
}

func (ca *transportCA) issue(t *testing.T, name string, dnsNames []string, ipAddrs []net.IP, usages []x509.ExtKeyUsage) (string, string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name},
		DNSNames:     dnsNames,
		IPAddresses:  ipAddrs,
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  usages,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &priv.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certFile := fmt.Sprintf("%s/%s.crt", ca.dir, name)
	keyFile := fmt.Sprintf("%s/%s.key", ca.dir, name)
	_ = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	_ = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certFile, keyFile
}

// freeTCPPort returns an available TCP port on 127.0.0.1.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// TestTLSTransportEndToEnd creates two uwgsocks engines connected over TLS
// and verifies WireGuard handshake + SOCKS5 HTTP reachability.
func TestTLSTransportEndToEnd(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	srv := startHTTPServer(t)
	defer srv.Close()

	ca := newTransportCA(t)
	serverCert, serverKey := ca.issueServer(t, "tls-server", []net.IP{net.ParseIP("127.0.0.1")})

	serverKey_, clientKey_ := mustKey(t), mustKey(t)
	tlsPort := freeTCPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey_.String()
	transparent := true
	serverCfg.Inbound.Transparent = &transparent
	serverCfg.WireGuard.Addresses = []string{"100.64.40.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey_.PublicKey().String(),
		AllowedIPs: []string{"100.64.40.2/32"},
		Transport:  "tls-server",
	}}
	serverCfg.Transports = []transport.Config{{
		Name:       "tls-server",
		Base:       "tls",
		Listen:     true,
		ListenPort: &tlsPort,
		TLS: transport.TLSConfig{
			CertFile: serverCert,
			KeyFile:  serverKey,
		},
	}}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey_.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.40.2/32"}
	clientCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey_.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", tlsPort),
		AllowedIPs:          []string{hostIP.String() + "/32"},
		PersistentKeepalive: 1,
		Transport:           "tls-client",
	}}
	clientCfg.Transports = []transport.Config{{
		Name: "tls-client",
		Base: "tls",
		TLS: transport.TLSConfig{
			VerifyPeer: true,
			CAFile:     ca.caFile,
		},
	}}
	clientEng := mustStart(t, clientCfg)
	defer clientEng.Close()

	target := net.JoinHostPort(hostIP.String(), srv.Port)
	body := socksHTTPGet(t, clientEng.Addr("socks5"), target)
	if body != "hello over wg" {
		t.Fatalf("TLS transport: unexpected body %q", body)
	}
	waitPeerStatus(t, clientEng, serverKey_.PublicKey().String())
	waitPeerStatus(t, serverEng, clientKey_.PublicKey().String())
}

// TestHTTPSTransportEndToEnd connects two engines over HTTPS WebSocket and
// verifies WireGuard handshake + SOCKS5 HTTP reachability.
func TestHTTPSTransportEndToEnd(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	srv := startHTTPServer(t)
	defer srv.Close()

	ca := newTransportCA(t)
	serverCert, serverKey := ca.issueServer(t, "https-server", []net.IP{net.ParseIP("127.0.0.1")})

	serverKey_, clientKey_ := mustKey(t), mustKey(t)
	httpsPort := freeTCPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey_.String()
	transparent := true
	serverCfg.Inbound.Transparent = &transparent
	serverCfg.WireGuard.Addresses = []string{"100.64.41.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey_.PublicKey().String(),
		AllowedIPs: []string{"100.64.41.2/32"},
		Transport:  "https-server",
	}}
	serverCfg.Transports = []transport.Config{{
		Name:       "https-server",
		Base:       "https",
		Listen:     true,
		ListenPort: &httpsPort,
		WebSocket:  transport.WebSocketConfig{Path: "/wg"},
		TLS: transport.TLSConfig{
			CertFile: serverCert,
			KeyFile:  serverKey,
		},
	}}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey_.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.41.2/32"}
	clientCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey_.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", httpsPort),
		AllowedIPs:          []string{hostIP.String() + "/32"},
		PersistentKeepalive: 1,
		Transport:           "https-client",
	}}
	clientCfg.Transports = []transport.Config{{
		Name:      "https-client",
		Base:      "https",
		WebSocket: transport.WebSocketConfig{Path: "/wg"},
		TLS: transport.TLSConfig{
			VerifyPeer: true,
			CAFile:     ca.caFile,
		},
	}}
	clientEng := mustStart(t, clientCfg)
	defer clientEng.Close()

	target := net.JoinHostPort(hostIP.String(), srv.Port)
	body := socksHTTPGet(t, clientEng.Addr("socks5"), target)
	if body != "hello over wg" {
		t.Fatalf("HTTPS transport: unexpected body %q", body)
	}
	waitPeerStatus(t, clientEng, serverKey_.PublicKey().String())
	waitPeerStatus(t, serverEng, clientKey_.PublicKey().String())
}

// TestQUICTransportEndToEnd connects two engines over QUIC WebTransport and
// verifies WireGuard handshake + SOCKS5 HTTP reachability.
func TestQUICTransportEndToEnd(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	srv := startHTTPServer(t)
	defer srv.Close()

	ca := newTransportCA(t)
	serverCert, serverKey := ca.issueServer(t, "quic-server", []net.IP{net.ParseIP("127.0.0.1")})

	serverKey_, clientKey_ := mustKey(t), mustKey(t)
	quicPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey_.String()
	transparent := true
	serverCfg.Inbound.Transparent = &transparent
	serverCfg.WireGuard.Addresses = []string{"100.64.42.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey_.PublicKey().String(),
		AllowedIPs: []string{"100.64.42.2/32"},
		Transport:  "quic-server",
	}}
	serverCfg.Transports = []transport.Config{{
		Name:       "quic-server",
		Base:       "quic",
		Listen:     true,
		ListenPort: &quicPort,
		WebSocket:  transport.WebSocketConfig{Path: "/wg"},
		TLS: transport.TLSConfig{
			CertFile: serverCert,
			KeyFile:  serverKey,
		},
	}}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey_.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.42.2/32"}
	clientCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey_.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", quicPort),
		AllowedIPs:          []string{hostIP.String() + "/32"},
		PersistentKeepalive: 1,
		Transport:           "quic-client",
	}}
	clientCfg.Transports = []transport.Config{{
		Name:      "quic-client",
		Base:      "quic",
		WebSocket: transport.WebSocketConfig{Path: "/wg"},
		TLS: transport.TLSConfig{
			VerifyPeer: true,
			CAFile:     ca.caFile,
		},
	}}
	clientEng := mustStart(t, clientCfg)
	defer clientEng.Close()

	target := net.JoinHostPort(hostIP.String(), srv.Port)
	body := socksHTTPGet(t, clientEng.Addr("socks5"), target)
	if body != "hello over wg" {
		t.Fatalf("QUIC transport: unexpected body %q", body)
	}
	waitPeerStatus(t, clientEng, serverKey_.PublicKey().String())
	waitPeerStatus(t, serverEng, clientKey_.PublicKey().String())
}

// TestNamedUDPTransportEndToEnd verifies that a server with an explicit named
// UDP transport (listen: true, listen_port: N) works correctly when paired
// with a client that has no transports section (uses the legacy UDP bind).
// This is the exact scenario from examples/exit-server.yaml + exit-client.yaml.
func TestNamedUDPTransportEndToEnd(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	srv := startHTTPServer(t)
	defer srv.Close()

	serverKey_, clientKey_ := mustKey(t), mustKey(t)
	udpPort := freeUDPPort(t)

	// Server: named UDP transport with explicit listen_port.
	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey_.String()
	transparent := true
	serverCfg.Inbound.Transparent = &transparent
	serverCfg.WireGuard.Addresses = []string{"100.64.43.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey_.PublicKey().String(),
		AllowedIPs: []string{"100.64.43.2/32"},
	}}
	listenPort := udpPort
	serverCfg.Transports = []transport.Config{{
		Name:       "udp",
		Base:       "udp",
		Listen:     true,
		ListenPort: &listenPort,
	}}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	// Client: no transports section — uses legacy OutboundOnlyBind.
	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey_.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.43.2/32"}
	clientCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey_.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", udpPort),
		AllowedIPs:          []string{hostIP.String() + "/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)
	defer clientEng.Close()

	target := net.JoinHostPort(hostIP.String(), srv.Port)
	body := socksHTTPGet(t, clientEng.Addr("socks5"), target)
	if body != "hello over wg" {
		t.Fatalf("named UDP transport: unexpected body %q", body)
	}
	waitPeerStatus(t, clientEng, serverKey_.PublicKey().String())
	waitPeerStatus(t, serverEng, clientKey_.PublicKey().String())
}
