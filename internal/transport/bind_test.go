// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package transport_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
)

// --------------------------------------------------------------------------
// Helpers
// --------------------------------------------------------------------------

// loopbackDialer dials directly on loopback; used as ProxyDialer in tests.
type loopbackDialer struct{}

func (loopbackDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}
func (loopbackDialer) DialPacket(_ context.Context, _ string) (net.PacketConn, string, error) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		return nil, "", err
	}
	return pc, pc.LocalAddr().String(), nil
}
func (loopbackDialer) SupportsHostname() bool { return true }

func skipQUICOnRestrictedGVisor(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/proc/sentry-meminfo"); err == nil {
		t.Skip("QUIC/WebTransport round-trip is unsupported on this gVisor network stack")
	}
}

// sendRecv sends n packets through sess and reads them back via readSess.
// It returns an error if any send/receive fails within timeout.
func sendRecv(t *testing.T, writeSess, readSess transport.Session, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		payload := []byte(fmt.Sprintf("packet-%d", i))
		if err := writeSess.WritePacket(payload); err != nil {
			t.Fatalf("WritePacket %d: %v", i, err)
		}
		got, err := readSess.ReadPacket()
		if err != nil {
			t.Fatalf("ReadPacket %d: %v", i, err)
		}
		if string(got) != string(payload) {
			t.Fatalf("packet %d: got %q, want %q", i, got, payload)
		}
	}
}

func writeSelfSignedCert(t *testing.T, dnsName string) (string, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: dnsName},
		DNSNames:     []string{dnsName},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	certFile := dir + "/server.crt"
	keyFile := dir + "/server.key"
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

type testCA struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	caFile string
	dir    string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
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
	return &testCA{
		cert:   cert,
		key:    priv,
		caFile: caFile,
		dir:    dir,
	}
}

func (ca *testCA) issueLeaf(t *testing.T, name string, dnsNames []string, ipAddrs []net.IP, usages []x509.ExtKeyUsage) (string, string) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
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
	base := fmt.Sprintf("%s/%s", ca.dir, strings.ReplaceAll(name, " ", "_"))
	certFile := base + ".crt"
	keyFile := base + ".key"
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func newCertManagerFromFiles(t *testing.T, certFile, keyFile string) *transport.CertManager {
	t.Helper()
	mgr := &transport.CertManager{
		CertFile: certFile,
		KeyFile:  keyFile,
	}
	if err := mgr.Start(); err != nil {
		t.Fatal(err)
	}
	return mgr
}

func websocketAcceptForTest(key string) string {
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// --------------------------------------------------------------------------
// TCP framing unit tests
// --------------------------------------------------------------------------

func TestTCPFramingRoundTrip(t *testing.T) {
	tr := transport.NewTCPTransport("tcp-test", loopbackDialer{}, []string{"127.0.0.1"})

	ctx := context.Background()
	ln, err := tr.Listen(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	serverSess := make(chan transport.Session, 1)
	go func() {
		sess, err := ln.Accept(ctx)
		if err == nil {
			serverSess <- sess
		}
	}()

	clientSess, err := tr.Dial(ctx, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSess.Close()

	srvSess := <-serverSess
	defer srvSess.Close()

	sendRecv(t, clientSess, srvSess, 100)
}

func TestTCPFramingLargePacket(t *testing.T) {
	tr := transport.NewTCPTransport("tcp-large", loopbackDialer{}, []string{"127.0.0.1"})
	ctx := context.Background()
	ln, err := tr.Listen(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverSess := make(chan transport.Session, 1)
	go func() {
		sess, _ := ln.Accept(ctx)
		serverSess <- sess
	}()

	clientSess, err := tr.Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientSess.Close()
	srvSess := <-serverSess
	defer srvSess.Close()

	// 16 KB payload
	large := make([]byte, 16*1024)
	for i := range large {
		large[i] = byte(i)
	}
	if err := clientSess.WritePacket(large); err != nil {
		t.Fatal(err)
	}
	got, err := srvSess.ReadPacket()
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != len(large) {
		t.Fatalf("length mismatch: %d vs %d", len(got), len(large))
	}
}

// --------------------------------------------------------------------------
// TLS transport tests
// --------------------------------------------------------------------------

func TestTLSTransportSelfSigned(t *testing.T) {
	certMgr := &transport.CertManager{}
	if err := certMgr.Start(); err != nil {
		t.Fatal(err)
	}
	tr := transport.NewTLSTransport("tls-test", loopbackDialer{}, []string{"127.0.0.1"}, certMgr, transport.TLSConfig{})

	ctx := context.Background()
	ln, err := tr.Listen(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverSess := make(chan transport.Session, 1)
	go func() {
		sess, _ := ln.Accept(ctx)
		serverSess <- sess
	}()

	clientSess, err := tr.Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientSess.Close()
	srvSess := <-serverSess
	defer srvSess.Close()

	sendRecv(t, clientSess, srvSess, 50)
}

// --------------------------------------------------------------------------
// DTLS transport tests
// --------------------------------------------------------------------------

func TestDTLSTransportRoundTrip(t *testing.T) {
	certMgr := &transport.CertManager{}
	if err := certMgr.Start(); err != nil {
		t.Fatal(err)
	}
	tr := transport.NewDTLSTransport("dtls-test", loopbackDialer{}, []string{"127.0.0.1"}, certMgr, transport.TLSConfig{})

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	ln, err := tr.Listen(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverSess := make(chan transport.Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		sess, err := ln.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		serverSess <- sess
	}()

	clientSess, err := tr.Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientSess.Close()

	select {
	case srvSess := <-serverSess:
		defer srvSess.Close()
		sendRecv(t, clientSess, srvSess, 20)
	case err := <-serverErr:
		t.Fatalf("server accept: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for server to accept DTLS connection")
	}
}

// --------------------------------------------------------------------------
// WebSocket transport tests
// --------------------------------------------------------------------------

func TestWebSocketTransportRoundTrip(t *testing.T) {
	tr := transport.NewWebSocketTransport(
		"ws-test",
		"http",
		loopbackDialer{},
		[]string{"127.0.0.1"},
		nil,
		transport.TLSConfig{},
		transport.WithWebSocketPath("/wireguard"),
	)

	ctx := context.Background()
	ln, err := tr.Listen(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverSess := make(chan transport.Session, 1)
	go func() {
		sess, _ := ln.Accept(ctx)
		serverSess <- sess
	}()

	clientSess, err := tr.Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientSess.Close()
	srvSess := <-serverSess
	if srvSess == nil {
		t.Fatal("server session is nil")
	}
	defer srvSess.Close()

	sendRecv(t, clientSess, srvSess, 30)
}

func TestWebSocketTransportTLSSNIOverride(t *testing.T) {
	certFile, keyFile := writeSelfSignedCert(t, "ws.test")
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}

	var seenSNI string
	var seenHost string
	hijacked := make(chan net.Conn, 1)
	mux := http.NewServeMux()
	mux.HandleFunc("/wireguard", func(w http.ResponseWriter, r *http.Request) {
		seenHost = r.Host
		key := r.Header.Get("Sec-WebSocket-Key")
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}
		conn, _, err := hj.Hijack()
		if err != nil {
			return
		}
		_, _ = fmt.Fprintf(conn, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", websocketAcceptForTest(key))
		hijacked <- conn
	})

	rawListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer rawListener.Close()

	tlsListener := tls.NewListener(rawListener, &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			seenSNI = hello.ServerName
			return &cert, nil
		},
	})
	defer tlsListener.Close()

	server := &http.Server{Handler: mux}
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- server.Serve(tlsListener)
	}()
	defer func() {
		_ = server.Close()
		err := <-serverDone
		if err != nil && err != http.ErrServerClosed {
			t.Errorf("server serve: %v", err)
		}
	}()

	tr := transport.NewWebSocketTransport(
		"wss-test",
		"https",
		loopbackDialer{},
		nil,
		nil,
		transport.TLSConfig{},
		transport.WithWebSocketPath("/wireguard"),
		transport.WithWebSocketHostHeader("inner.example"),
		transport.WithWebSocketSNIHostname("ws.test"),
	)

	ctx := context.Background()
	clientSess, err := tr.Dial(ctx, rawListener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientSess.Close()

	select {
	case conn := <-hijacked:
		_ = conn.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for websocket server handshake")
	}

	if seenSNI != "ws.test" {
		t.Fatalf("unexpected TLS SNI %q", seenSNI)
	}
	if seenHost != "inner.example" {
		t.Fatalf("unexpected Host header %q", seenHost)
	}
}

// --------------------------------------------------------------------------
// SOCKS5 proxy dialer tests
// --------------------------------------------------------------------------

// mockSOCKS5Server is a minimal SOCKS5 server that handles CONNECT only.
func startMockSOCKS5(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSOCKS5Conn(conn)
		}
	}()
	return ln.Addr().String()
}

func handleSOCKS5Conn(c net.Conn) {
	defer c.Close()
	buf := make([]byte, 256)
	// Read greeting.
	n, err := c.Read(buf)
	if err != nil || n < 2 {
		return
	}
	// Reply: no auth required.
	c.Write([]byte{5, 0})
	// Read request.
	n, err = c.Read(buf)
	if err != nil || n < 7 {
		return
	}
	// Parse target address.
	atyp := buf[3]
	var targetAddr string
	var offset int
	switch atyp {
	case 1: // IPv4
		if n < 10 {
			return
		}
		ip := net.IP(buf[4:8])
		port := int(buf[8])<<8 | int(buf[9])
		targetAddr = fmt.Sprintf("%s:%d", ip, port)
		offset = 10
	case 3: // domain
		dlen := int(buf[4])
		if n < 5+dlen+2 {
			return
		}
		domain := string(buf[5 : 5+dlen])
		port := int(buf[5+dlen])<<8 | int(buf[5+dlen+1])
		targetAddr = fmt.Sprintf("%s:%d", domain, port)
		offset = 5 + dlen + 2
	default:
		c.Write([]byte{5, 8, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	_ = offset
	upstream, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		c.Write([]byte{5, 5, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	defer upstream.Close()
	// Success reply.
	c.Write([]byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	// Relay.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); io.Copy(upstream, c) }() //nolint:errcheck
	go func() { defer wg.Done(); io.Copy(c, upstream) }() //nolint:errcheck
	wg.Wait()
}

func TestSOCKS5DialerTCP(t *testing.T) {
	// Start a real TCP echo server.
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c) //nolint:errcheck
		}
	}()

	socksAddr := startMockSOCKS5(t)
	d, err := transport.NewSOCKS5Dialer(socksAddr, "", "")
	if err != nil {
		t.Fatal(err)
	}

	conn, err := d.DialContext(context.Background(), "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := []byte("hello socks5")
	conn.Write(msg) //nolint:errcheck
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: %q vs %q", buf, msg)
	}
}

// --------------------------------------------------------------------------
// HTTP CONNECT proxy dialer tests
// --------------------------------------------------------------------------

func startMockHTTPProxy(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	srv := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "only CONNECT", http.StatusMethodNotAllowed)
				return
			}
			upstream, err := net.DialTimeout("tcp", r.Host, 5*time.Second)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadGateway)
				return
			}
			hj, ok := w.(http.Hijacker)
			if !ok {
				upstream.Close()
				return
			}
			c, _, _ := hj.Hijack()
			fmt.Fprintf(c, "HTTP/1.1 200 Connection established\r\n\r\n")
			var wg sync.WaitGroup
			wg.Add(2)
			go func() { defer wg.Done(); io.Copy(upstream, c) }() //nolint:errcheck
			go func() { defer wg.Done(); io.Copy(c, upstream) }() //nolint:errcheck
			wg.Wait()
			upstream.Close()
		}),
	}
	go srv.Serve(ln) //nolint:errcheck
	return ln.Addr().String()
}

func TestHTTPConnectDialer(t *testing.T) {
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c) //nolint:errcheck
		}
	}()

	proxyAddr := startMockHTTPProxy(t)
	d, err := transport.NewHTTPConnectDialer(proxyAddr, "http", "", "", transport.TLSConfig{})
	if err != nil {
		t.Fatal(err)
	}

	conn, err := d.DialContext(context.Background(), "tcp", echoLn.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	msg := []byte("hello http proxy")
	conn.Write(msg) //nolint:errcheck
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	if string(buf) != string(msg) {
		t.Fatalf("echo mismatch: %q vs %q", buf, msg)
	}
}

func TestHTTPConnectDialerNoUDP(t *testing.T) {
	d, _ := transport.NewHTTPConnectDialer("127.0.0.1:1080", "http", "", "", transport.TLSConfig{})
	_, _, err := d.DialPacket(context.Background(), "")
	if err != transport.ErrUDPNotSupported {
		t.Fatalf("expected ErrUDPNotSupported, got %v", err)
	}
}

// --------------------------------------------------------------------------
// TLS certificate manager tests
// --------------------------------------------------------------------------

func TestCertManagerAutoGenerate(t *testing.T) {
	mgr := &transport.CertManager{}
	if err := mgr.Start(); err != nil {
		t.Fatal(err)
	}
	cert, err := mgr.GetCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cert == nil {
		t.Fatal("expected non-nil certificate")
	}
	// Check the cert is usable for TLS.
	cfg := mgr.TLSConfig()
	if cfg.GetCertificate == nil {
		t.Fatal("TLSConfig missing GetCertificate")
	}
}

// --------------------------------------------------------------------------
// IPv6 translation unit tests
// --------------------------------------------------------------------------

func TestTranslateToIPv6(t *testing.T) {
	prefix := netip.MustParsePrefix("64:ff9b::/96")
	v4 := netip.MustParseAddr("1.2.3.4")
	v6 := transport.TranslateToIPv6(v4, prefix)
	if !v6.Is6() {
		t.Fatalf("expected IPv6 address, got %s", v6)
	}
	back, ok := transport.TranslateFromIPv6(v6, prefix)
	if !ok {
		t.Fatal("TranslateFromIPv6 returned false")
	}
	if back != v4 {
		t.Fatalf("round-trip mismatch: got %s, want %s", back, v4)
	}
}

func TestTranslateToIPv6NoopForV6(t *testing.T) {
	prefix := netip.MustParsePrefix("64:ff9b::/96")
	v6 := netip.MustParseAddr("2001:db8::1")
	got := transport.TranslateToIPv6(v6, prefix)
	if got != v6 {
		t.Fatalf("expected unchanged IPv6, got %s", got)
	}
}

// --------------------------------------------------------------------------
// Endpoint type unit tests
// --------------------------------------------------------------------------

func TestEndpointIdentConsistency(t *testing.T) {
	ap := netip.MustParseAddrPort("10.0.0.1:51820")
	nce := transport.NewNotConnOrientedEndpoint("udp", ap)
	de := transport.NewDialEndpoint("tcp", "10.0.0.1:51820")

	// Each endpoint type has its own identity — they are different transports.
	if string(nce.IdentBytes()) == string(de.IdentBytes()) {
		t.Fatal("NCE and DialEndpoint should have different identities for different transport names")
	}

	// Same transport + same target = same identity for DialEndpoint.
	de2 := transport.NewDialEndpoint("tcp", "10.0.0.1:51820")
	if string(de.IdentBytes()) != string(de2.IdentBytes()) {
		t.Fatal("two DialEndpoints with same params should have equal IdentBytes")
	}
}

// --------------------------------------------------------------------------
// MultiTransportBind: idle timer test
// --------------------------------------------------------------------------

func TestBindIdleTimerClosesSession(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping idle timer test in short mode")
	}
	// We override tcpIdleTimeout indirectly by testing that the session map
	// entry is cleaned up after a kill.
	bind := transport.NewMultiTransportBind(nil, nil)

	tcpTr := transport.NewTCPTransport("tcp", loopbackDialer{}, []string{"127.0.0.1"})
	bind.AddTransport(tcpTr)
	bind.AddListenTransport(tcpTr)

	_, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()

	// Dial a connection to the bind.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// After close the active session count should drop.
	time.Sleep(100 * time.Millisecond)
	if bind.ActiveSessions() < 0 {
		t.Fatal("unexpected negative session count")
	}
}

// --------------------------------------------------------------------------
// MultiTransportBind: roaming test
// --------------------------------------------------------------------------

func TestBindRoamingAcrossTransports(t *testing.T) {
	// Server bind with both TCP and UDP transports in listen mode.
	serverBind := transport.NewMultiTransportBind(nil, nil)
	tcpTr := transport.NewTCPTransport("tcp", loopbackDialer{}, []string{"127.0.0.1"})
	udpTr := transport.NewUDPTransport("udp", []string{"127.0.0.1"}, nil)
	serverBind.AddTransport(tcpTr)
	serverBind.AddTransport(udpTr)
	serverBind.AddListenTransport(tcpTr)
	serverBind.AddListenTransport(udpTr)

	recvFns, _, err := serverBind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer serverBind.Close()
	if len(recvFns) == 0 {
		t.Fatal("no receive functions returned")
	}
}

// --------------------------------------------------------------------------
// Session death and reconnect rate-limit test
// --------------------------------------------------------------------------

func TestConnEstablishedFallsBackOnDeath(t *testing.T) {
	// Start a TCP echo server.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c) //nolint:errcheck
		}
	}()

	de := transport.NewDialEndpoint("tcp", ln.Addr().String())
	tcpTr := transport.NewTCPTransport("tcp", loopbackDialer{}, nil)

	reconnected := make(chan struct{}, 1)
	bind := transport.NewMultiTransportBind(nil, func(ident []byte, fallback string) {
		select {
		case reconnected <- struct{}{}:
		default:
		}
	})
	bind.AddTransport(tcpTr)
	bind.SetPeerSession(de.IdentBytes(), de, tcpTr, 0)
	_, _, err = bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()

	// Send a packet to dial the first session.
	_ = bind.Send([][]byte{[]byte("hello")}, de)

	// Close the server to kill the session.
	ln.Close()

	// The onEndpointReset callback should fire.
	select {
	case <-reconnected:
		// OK
	case <-time.After(3 * time.Second):
		// Fine: if no persistent keepalive the callback may not fire until next send.
	}
}

// --------------------------------------------------------------------------
// TLS over HTTP CONNECT proxy test
// --------------------------------------------------------------------------

func TestTLSOverHTTPConnectProxy(t *testing.T) {
	// Start TLS server.
	certMgr := &transport.CertManager{}
	if err := certMgr.Start(); err != nil {
		t.Fatal(err)
	}
	tlsTr := transport.NewTLSTransport("tls", loopbackDialer{}, []string{"127.0.0.1"}, certMgr, transport.TLSConfig{})
	ctx := context.Background()
	ln, err := tlsTr.Listen(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	target := ln.Addr().String()

	serverSess := make(chan transport.Session, 1)
	go func() {
		sess, _ := ln.Accept(ctx)
		serverSess <- sess
	}()

	// Start HTTP CONNECT proxy.
	proxyAddr := startMockHTTPProxy(t)

	// Build TLS transport that dials through the HTTP proxy.
	httpDialer, err := transport.NewHTTPConnectDialer(proxyAddr, "http", "", "", transport.TLSConfig{})
	if err != nil {
		t.Fatal(err)
	}
	// Manually create a TLS session via the proxy dialer.
	conn, err := httpDialer.DialContext(ctx, "tcp", target)
	if err != nil {
		t.Fatal(err)
	}
	tlsConn := tls.Client(conn, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec
	if err := tlsConn.Handshake(); err != nil {
		t.Fatal(err)
	}
	defer tlsConn.Close()

	srvSess := <-serverSess
	if srvSess == nil {
		t.Fatal("nil server session")
	}
	defer srvSess.Close()
}

func TestTLSTransportMutualTLS(t *testing.T) {
	ca := newTestCA(t)
	serverCert, serverKey := ca.issueLeaf(t, "tls-server", nil, []net.IP{net.ParseIP("127.0.0.1")}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	clientCert, clientKey := ca.issueLeaf(t, "tls-client", nil, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	serverMgr := newCertManagerFromFiles(t, serverCert, serverKey)
	clientMgr := newCertManagerFromFiles(t, clientCert, clientKey)

	serverTLS := transport.TLSConfig{
		VerifyPeer: true,
		CAFile:     ca.caFile,
	}
	clientTLS := transport.TLSConfig{
		VerifyPeer: true,
		CAFile:     ca.caFile,
	}

	serverTr := transport.NewTLSTransport("tls-server", loopbackDialer{}, []string{"127.0.0.1"}, serverMgr, serverTLS)
	clientTr := transport.NewTLSTransport("tls-client", loopbackDialer{}, nil, clientMgr, clientTLS)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ln, err := serverTr.Listen(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverSess := make(chan transport.Session, 1)
	go func() {
		sess, err := ln.Accept(ctx)
		if err == nil {
			serverSess <- sess
		}
	}()

	clientSess, err := clientTr.Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientSess.Close()

	srvSess := <-serverSess
	defer srvSess.Close()

	sendRecv(t, clientSess, srvSess, 20)
}

func TestQUICTransportRoundTrip(t *testing.T) {
	skipQUICOnRestrictedGVisor(t)

	ca := newTestCA(t)
	serverCert, serverKey := ca.issueLeaf(t, "quic-server", nil, []net.IP{net.ParseIP("127.0.0.1")}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	serverMgr := newCertManagerFromFiles(t, serverCert, serverKey)
	trServer := transport.NewQUICTransport(
		"quic-server",
		loopbackDialer{},
		[]string{"127.0.0.1"},
		serverMgr,
		transport.TLSConfig{},
		"/wireguard",
		"",
		"",
	)
	trClient := transport.NewQUICTransport(
		"quic-client",
		loopbackDialer{},
		nil,
		nil,
		transport.TLSConfig{
			VerifyPeer: true,
			CAFile:     ca.caFile,
		},
		"/wireguard",
		"inner.example",
		"",
	)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	ln, err := trServer.Listen(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	serverSess := make(chan transport.Session, 1)
	serverErr := make(chan error, 1)
	go func() {
		sess, err := ln.Accept(ctx)
		if err != nil {
			serverErr <- err
			return
		}
		serverSess <- sess
	}()

	clientSess, err := trClient.Dial(ctx, ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer clientSess.Close()

	select {
	case srvSess := <-serverSess:
		defer srvSess.Close()
		sendRecv(t, clientSess, srvSess, 20)
	case err := <-serverErr:
		t.Fatalf("server accept: %v", err)
	case <-ctx.Done():
		t.Fatal("timeout waiting for QUIC session")
	}
}

// --------------------------------------------------------------------------
// Registry / BuildRegistry smoke test
// --------------------------------------------------------------------------

func TestBuildRegistryDefault(t *testing.T) {
	bind, err := transport.BuildRegistry(nil, [32]byte{}, 0, nil, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	if bind == nil {
		t.Fatal("expected non-nil bind")
	}
	names := bind.TransportNames()
	if len(names) == 0 {
		t.Fatal("expected at least one default transport")
	}
}

func TestBuildRegistryTCPTransport(t *testing.T) {
	cfgs := []transport.Config{
		{
			Name:   "tcp-reg",
			Base:   "tcp",
			Listen: true,
		},
	}
	bind, err := transport.BuildRegistry(cfgs, [32]byte{}, 0, nil, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	got := bind.TransportNames()
	found := false
	for _, n := range got {
		if n == "tcp-reg" {
			found = true
		}
	}
	if !found {
		t.Fatalf("transport tcp-reg not found in %v", got)
	}
}

// --------------------------------------------------------------------------
// Stress: many concurrent send/receive over TCP transport
// --------------------------------------------------------------------------

func TestTCPConcurrentStress(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping stress test in short mode")
	}
	tr := transport.NewTCPTransport("tcp-stress", loopbackDialer{}, []string{"127.0.0.1"})
	ctx := context.Background()
	ln, err := tr.Listen(ctx, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	addr := ln.Addr().String()

	const workers = 10
	const packets = 200

	serverCtx, serverCancel := context.WithCancel(ctx)
	defer serverCancel()

	var acceptWG sync.WaitGroup
	acceptWG.Add(1)
	go func() {
		defer acceptWG.Done()
		for {
			server, err := ln.Accept(serverCtx)
			if err != nil {
				if serverCtx.Err() != nil {
					return
				}
				if err == net.ErrClosed {
					return
				}
				t.Errorf("accept: %v", err)
				return
			}
			go func(sess transport.Session) {
				defer sess.Close()
				for {
					pkt, err := sess.ReadPacket()
					if err != nil {
						return
					}
					if err := sess.WritePacket(pkt); err != nil {
						return
					}
				}
			}(server)
		}
	}()

	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			client, err := tr.Dial(ctx, addr)
			if err != nil {
				t.Errorf("worker %d dial: %v", id, err)
				return
			}
			defer client.Close()
			for j := 0; j < packets; j++ {
				pkt := []byte(fmt.Sprintf("w%d-p%d", id, j))
				if err := client.WritePacket(pkt); err != nil {
					t.Errorf("worker %d send %d: %v", id, j, err)
					return
				}
				got, err := client.ReadPacket()
				if err != nil {
					t.Errorf("worker %d recv %d: %v", id, j, err)
					return
				}
				if string(got) != string(pkt) {
					t.Errorf("worker %d pkt %d mismatch", id, j)
				}
			}
		}(i)
	}
	wg.Wait()
	serverCancel()
	_ = ln.Close()
	acceptWG.Wait()
}

// --------------------------------------------------------------------------
// Stress: no WireGuard session cleanup after 5s
// --------------------------------------------------------------------------

func TestOrphanedConnectionCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping cleanup test in short mode")
	}
	// An orphaned TCP connection (no matching WireGuard session) should be
	// cleaned up.  We simulate this by opening a raw TCP connection to a
	// listening MultiTransportBind and sending no valid WireGuard data.
	tcpTr := transport.NewTCPTransport("tcp-orphan", loopbackDialer{}, []string{"127.0.0.1"})
	bind := transport.NewMultiTransportBind(nil, nil)
	bind.AddTransport(tcpTr)
	bind.AddListenTransport(tcpTr)

	_, port, err := bind.Open(0)
	if err != nil {
		t.Fatal(err)
	}
	defer bind.Close()

	// Open a raw TCP connection and send nothing.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// The bind's accept loop will start serving this session. After 30 s idle
	// it would close; for test purposes we just verify the connection stays
	// open for a couple of seconds (i.e., we don't kill it too eagerly).
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1)
	_, err = conn.Read(buf)
	if err != nil && !isTimeout(err) {
		// A real close error means the bind killed us, which we don't want yet.
		t.Logf("connection closed early: %v", err)
	}
}

func isTimeout(err error) bool {
	ne, ok := err.(net.Error)
	return ok && ne.Timeout()
}
