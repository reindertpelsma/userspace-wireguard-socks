package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	piondtls "github.com/pion/dtls/v3"
	turn "github.com/pion/turn/v4"
)

type turnTestCA struct {
	cert   *x509.Certificate
	key    *ecdsa.PrivateKey
	caFile string
	dir    string
}

func newTurnTestCA(t *testing.T) *turnTestCA {
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
		Subject:               pkix.Name{CommonName: "turn-test-ca"},
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
	caFile := filepath.Join(dir, "ca.crt")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	return &turnTestCA{
		cert:   cert,
		key:    priv,
		caFile: caFile,
		dir:    dir,
	}
}

func (ca *turnTestCA) issueLeaf(t *testing.T, name string, ipAddrs []net.IP, usages []x509.ExtKeyUsage) (string, string) {
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
	certFile := filepath.Join(ca.dir, name+".crt")
	keyFile := filepath.Join(ca.dir, name+".key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return certFile, keyFile
}

func loadTurnTestCertPool(t *testing.T, caFile string) *x509.CertPool {
	t.Helper()
	data, err := os.ReadFile(caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(data) {
		t.Fatal("failed to append CA cert")
	}
	return pool
}

func loadTurnTestKeyPair(t *testing.T, certFile, keyFile string) tls.Certificate {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestBuildPionServerAndRelayEcho(t *testing.T) {
	cfg := Config{
		Realm:         "example.org",
		Software:      "go-open-turn",
		AllocationTTL: "2m",
		NonceTTL:      "2m",
		Listen: ListenConfig{
			TurnListen: "127.0.0.1:0",
			RelayIP:    "127.0.0.1",
		},
		Users: []UserConfig{{
			Username:           "alice",
			Password:           "alice-pass",
			Port:               40000,
			PermissionBehavior: "allow",
			SourceNetworks:     []string{"127.0.0.0/8"},
		}},
	}
	server := newTestTURNServer(t, cfg)

	echoConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer echoConn.Close()
	go udpEchoServer(echoConn)

	client := newTestTURNClient(t, server.listenAddr.String(), "alice", "alice-pass", "example.org")
	relayConn := allocateRelay(t, client)
	defer relayConn.Close()

	peer := echoConn.LocalAddr().(*net.UDPAddr)
	if err := relayConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := relayConn.WriteTo([]byte("hello-turn"), peer); err != nil {
		t.Fatalf("write via relay: %v", err)
	}
	buf := make([]byte, 2048)
	n, from, err := relayConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("read via relay: %v", err)
	}
	if from.String() != peer.String() {
		t.Fatalf("unexpected peer: got %s want %s", from.String(), peer.String())
	}
	if got := string(buf[:n]); got != "hello-turn" {
		t.Fatalf("unexpected payload: %q", got)
	}
}

func TestLookupPortRangeMapping(t *testing.T) {
	cfg := Config{
		Realm:         "example.org",
		Software:      "go-open-turn",
		AllocationTTL: "1m",
		NonceTTL:      "1m",
		Listen: ListenConfig{
			TurnListen: "127.0.0.1:0",
			RelayIP:    "127.0.0.1",
		},
		PortRanges: []RangeConfig{{
			Start:              41000,
			End:                41010,
			Password:           "shared-range-secret",
			PermissionBehavior: "allow",
			SourceNetworks:     []string{"127.0.0.0/8"},
			MappedRange: MappedRangeConfig{
				IP:        "203.0.113.10",
				StartPort: 51000,
			},
		}},
	}
	wrapper, err := newOpenRelayPion(cfg)
	if err != nil {
		t.Fatal(err)
	}
	rule, err := wrapper.lookup("41005")
	if err != nil {
		t.Fatal(err)
	}
	if rule.Password != "shared-range-secret" {
		t.Fatalf("unexpected password %q", rule.Password)
	}
	if rule.RequestedPort != 41005 {
		t.Fatalf("unexpected port %d", rule.RequestedPort)
	}
	if rule.MappedAddr == nil || rule.MappedAddr.String() != "203.0.113.10:51005" {
		t.Fatalf("unexpected mapped address %v", rule.MappedAddr)
	}
}

func TestBuildPionServerMultiListenerAllocations(t *testing.T) {
	cfg := Config{
		Realm: "example.org",
		Listen: ListenConfig{
			RelayIP: "127.0.0.1",
		},
		Listeners: []TURNListenerConfig{
			{Type: "udp", Listen: "127.0.0.1:0"},
			{Type: "tcp", Listen: "127.0.0.1:0"},
			{Type: "tls", Listen: "127.0.0.1:0"},
			{Type: "dtls", Listen: "127.0.0.1:0"},
		},
		Users: []UserConfig{{
			Username:       "alice",
			Password:       "alice-pass",
			SourceNetworks: []string{"127.0.0.0/8"},
		}},
	}
	server := newTestTURNServer(t, cfg)

	for _, listenerType := range []string{"udp", "tcp", "tls", "dtls"} {
		t.Run(listenerType, func(t *testing.T) {
			client := newTestTURNClientWithTransport(t, server, listenerType, "alice", "alice-pass", "example.org")
			relayAddr, closeRelay := allocateRelayForTransport(t, client, listenerType)
			defer closeRelay()
			if relayAddr == nil {
				t.Fatalf("%s relay did not expose a local address", listenerType)
			}
		})
	}
}

func TestBuildPionServerTLSAndDTLSVerifyPeer(t *testing.T) {
	ca := newTurnTestCA(t)
	serverCert, serverKey := ca.issueLeaf(t, "turn-server", []net.IP{net.ParseIP("127.0.0.1")}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})
	clientCert, clientKey := ca.issueLeaf(t, "turn-client", nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth})

	cfg := Config{
		Realm: "example.org",
		Listen: ListenConfig{
			RelayIP: "127.0.0.1",
		},
		Listeners: []TURNListenerConfig{
			{
				Type:       "tls",
				Listen:     "127.0.0.1:0",
				CertFile:   serverCert,
				KeyFile:    serverKey,
				VerifyPeer: true,
				CAFile:     ca.caFile,
			},
			{
				Type:       "dtls",
				Listen:     "127.0.0.1:0",
				CertFile:   serverCert,
				KeyFile:    serverKey,
				VerifyPeer: true,
				CAFile:     ca.caFile,
			},
		},
		Users: []UserConfig{{
			Username:       "alice",
			Password:       "alice-pass",
			SourceNetworks: []string{"127.0.0.0/8"},
		}},
	}
	server := newTestTURNServer(t, cfg)

	roots := loadTurnTestCertPool(t, ca.caFile)
	clientPair := loadTurnTestKeyPair(t, clientCert, clientKey)

	for _, listenerType := range []string{"tls", "dtls"} {
		t.Run(listenerType, func(t *testing.T) {
			client := newTestTURNClientWithTransportTLSOptions(t, server, listenerType, "alice", "alice-pass", "example.org", &tls.Config{
				RootCAs:      roots,
				ServerName:   "127.0.0.1",
				Certificates: []tls.Certificate{clientPair},
			}, &piondtls.Config{
				RootCAs:      roots,
				ServerName:   "127.0.0.1",
				Certificates: []tls.Certificate{clientPair},
			})
			relayAddr, closeRelay := allocateRelayForTransport(t, client, listenerType)
			defer closeRelay()
			if relayAddr == nil {
				t.Fatalf("%s relay did not expose a local address", listenerType)
			}
		})
	}
}

func TestBuildPionServerTLSAndDTLSRejectMissingClientCert(t *testing.T) {
	ca := newTurnTestCA(t)
	serverCert, serverKey := ca.issueLeaf(t, "turn-server", []net.IP{net.ParseIP("127.0.0.1")}, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth})

	cfg := Config{
		Realm: "example.org",
		Listen: ListenConfig{
			RelayIP: "127.0.0.1",
		},
		Listeners: []TURNListenerConfig{
			{
				Type:       "tls",
				Listen:     "127.0.0.1:0",
				CertFile:   serverCert,
				KeyFile:    serverKey,
				VerifyPeer: true,
				CAFile:     ca.caFile,
			},
			{
				Type:       "dtls",
				Listen:     "127.0.0.1:0",
				CertFile:   serverCert,
				KeyFile:    serverKey,
				VerifyPeer: true,
				CAFile:     ca.caFile,
			},
		},
		Users: []UserConfig{{
			Username:       "alice",
			Password:       "alice-pass",
			SourceNetworks: []string{"127.0.0.0/8"},
		}},
	}
	server := newTestTURNServer(t, cfg)
	roots := loadTurnTestCertPool(t, ca.caFile)

	t.Run("tls", func(t *testing.T) {
		addr := server.listenerAddrByType("tls")
		if addr == nil {
			t.Fatal("tls listener not found")
		}
		conn, err := tls.Dial("tcp", addr.String(), &tls.Config{
			RootCAs:    roots,
			ServerName: "127.0.0.1",
		})
		if err == nil {
			defer conn.Close()
			client, err := turn.NewClient(&turn.ClientConfig{
				STUNServerAddr: addr.String(),
				TURNServerAddr: addr.String(),
				Conn:           turn.NewSTUNConn(conn),
				Username:       "alice",
				Password:       "alice-pass",
				Realm:          "example.org",
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.Listen(); err == nil {
				if allocation, allocErr := client.AllocateTCP(); allocErr == nil {
					_ = allocation.Close()
					t.Fatal("expected TLS client cert validation failure")
				}
			}
		}
	})

	t.Run("dtls", func(t *testing.T) {
		addr := server.listenerAddrByType("dtls")
		if addr == nil {
			t.Fatal("dtls listener not found")
		}
		udpAddr, err := net.ResolveUDPAddr("udp", addr.String())
		if err != nil {
			t.Fatal(err)
		}
		conn, err := piondtls.Dial("udp", udpAddr, &piondtls.Config{
			RootCAs:    roots,
			ServerName: "127.0.0.1",
		})
		if err == nil {
			defer conn.Close()
			client, err := turn.NewClient(&turn.ClientConfig{
				STUNServerAddr: addr.String(),
				TURNServerAddr: addr.String(),
				Conn:           turn.NewSTUNConn(conn),
				Username:       "alice",
				Password:       "alice-pass",
				Realm:          "example.org",
			})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if err := client.Listen(); err == nil {
				if relayConn, allocErr := client.Allocate(); allocErr == nil {
					_ = relayConn.Close()
					t.Fatal("expected DTLS client cert validation failure")
				}
			}
		}
	})
}

func TestAllowPeerRespectsSourceNetworks(t *testing.T) {
	_, srcNet, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	wrapper := &openRelayPion{
		clientReservations: map[string]*relayReservation{
			"127.0.0.1:50000": {
				Username: "alice",
				Sources:  []*net.IPNet{srcNet},
			},
		},
	}
	if !wrapper.allowPeer(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}, net.ParseIP("127.0.0.2")) {
		t.Fatal("expected loopback peer to be allowed")
	}
	if wrapper.allowPeer(&net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 50000}, net.ParseIP("192.0.2.1")) {
		t.Fatal("expected non-whitelisted peer to be denied")
	}
}

func TestInternalRelayOptimizationBetweenClients(t *testing.T) {
	cfg := Config{
		Realm: "example.org",
		Listen: ListenConfig{
			TurnListen: "127.0.0.1:0",
			RelayIP:    "127.0.0.1",
		},
		Users: []UserConfig{
			{Username: "alice", Password: "alice-pass", Port: 40100, SourceNetworks: []string{"127.0.0.0/8"}},
			{Username: "bob", Password: "bob-pass", Port: 40101, SourceNetworks: []string{"127.0.0.0/8"}},
		},
	}
	server := newTestTURNServer(t, cfg)

	alice := newTestTURNClient(t, server.listenAddr.String(), "alice", "alice-pass", "example.org")
	aliceRelay := allocateRelay(t, alice)
	defer aliceRelay.Close()

	bob := newTestTURNClient(t, server.listenAddr.String(), "bob", "bob-pass", "example.org")
	bobRelay := allocateRelay(t, bob)
	defer bobRelay.Close()

	if err := alice.CreatePermission(bobRelay.LocalAddr()); err != nil {
		t.Fatalf("alice create permission: %v", err)
	}
	if err := bob.CreatePermission(aliceRelay.LocalAddr()); err != nil {
		t.Fatalf("bob create permission: %v", err)
	}

	if err := bobRelay.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := aliceRelay.WriteTo([]byte("hello-bob"), bobRelay.LocalAddr()); err != nil {
		t.Fatalf("alice relay write: %v", err)
	}

	buf := make([]byte, 2048)
	n, from, err := bobRelay.ReadFrom(buf)
	if err != nil {
		t.Fatalf("bob relay read: %v", err)
	}
	if got := string(buf[:n]); got != "hello-bob" {
		t.Fatalf("unexpected payload %q", got)
	}
	if from.String() != aliceRelay.LocalAddr().String() {
		t.Fatalf("unexpected source %s", from)
	}
	if atomic.LoadInt64(&server.internalPackets) == 0 {
		t.Fatal("expected at least one internally routed TURN packet")
	}
}

func TestOutboundOnlyRequiresPriorSend(t *testing.T) {
	cfg := Config{
		Realm: "example.org",
		Listen: ListenConfig{
			TurnListen: "127.0.0.1:0",
			RelayIP:    "127.0.0.1",
		},
		Users: []UserConfig{{
			Username:       "alice",
			Password:       "alice-pass",
			Port:           40110,
			SourceNetworks: []string{"127.0.0.0/8"},
			OutboundOnly:   true,
		}},
	}
	server := newTestTURNServer(t, cfg)
	client := newTestTURNClient(t, server.listenAddr.String(), "alice", "alice-pass", "example.org")
	relayConn := allocateRelay(t, client)
	defer relayConn.Close()

	peerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()

	if err := client.CreatePermission(peerConn.LocalAddr()); err != nil {
		t.Fatalf("create permission: %v", err)
	}

	if _, err := peerConn.WriteToUDP([]byte("unsolicited"), relayConn.LocalAddr().(*net.UDPAddr)); err != nil {
		t.Fatalf("peer unsolicited send: %v", err)
	}
	assertReadTimeout(t, relayConn)

	replyDone := make(chan struct{})
	go func() {
		defer close(replyDone)
		buf := make([]byte, 1024)
		n, addr, err := peerConn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if string(buf[:n]) != "ping" {
			return
		}
		_, _ = peerConn.WriteToUDP([]byte("pong"), addr)
	}()

	if err := relayConn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := relayConn.WriteTo([]byte("ping"), peerConn.LocalAddr()); err != nil {
		t.Fatalf("relay outbound write: %v", err)
	}
	buf := make([]byte, 1024)
	n, from, err := relayConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("relay inbound reply: %v", err)
	}
	if got := string(buf[:n]); got != "pong" {
		t.Fatalf("unexpected reply %q", got)
	}
	if from.String() != peerConn.LocalAddr().String() {
		t.Fatalf("unexpected reply source %s", from)
	}
	<-replyDone
}

func TestInternalOnlyBlocksExternalTraffic(t *testing.T) {
	cfg := Config{
		Realm: "example.org",
		Listen: ListenConfig{
			TurnListen: "127.0.0.1:0",
			RelayIP:    "127.0.0.1",
		},
		Users: []UserConfig{
			{
				Username:       "alice",
				Password:       "alice-pass",
				Port:           40120,
				SourceNetworks: []string{"127.0.0.0/8"},
				InternalOnly:   true,
			},
			{
				Username:       "bob",
				Password:       "bob-pass",
				Port:           40121,
				SourceNetworks: []string{"127.0.0.0/8"},
			},
		},
	}
	server := newTestTURNServer(t, cfg)

	alice := newTestTURNClient(t, server.listenAddr.String(), "alice", "alice-pass", "example.org")
	aliceRelay := allocateRelay(t, alice)
	defer aliceRelay.Close()
	hostProbe, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: aliceRelay.LocalAddr().(*net.UDPAddr).Port,
	})
	if err != nil {
		t.Fatalf("expected internal-only relay port %d to stay unbound on host: %v", aliceRelay.LocalAddr().(*net.UDPAddr).Port, err)
	}
	_ = hostProbe.Close()

	bob := newTestTURNClient(t, server.listenAddr.String(), "bob", "bob-pass", "example.org")
	bobRelay := allocateRelay(t, bob)
	defer bobRelay.Close()

	if err := alice.CreatePermission(bobRelay.LocalAddr()); err != nil {
		t.Fatalf("alice create permission for bob: %v", err)
	}
	if err := bob.CreatePermission(aliceRelay.LocalAddr()); err != nil {
		t.Fatalf("bob create permission for alice: %v", err)
	}
	if err := bobRelay.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := aliceRelay.WriteTo([]byte("internal"), bobRelay.LocalAddr()); err != nil {
		t.Fatalf("internal-only relay internal write: %v", err)
	}
	buf := make([]byte, 1024)
	n, _, err := bobRelay.ReadFrom(buf)
	if err != nil {
		t.Fatalf("internal-only relay internal read: %v", err)
	}
	if got := string(buf[:n]); got != "internal" {
		t.Fatalf("unexpected internal payload %q", got)
	}

	peerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer peerConn.Close()
	if err := alice.CreatePermission(peerConn.LocalAddr()); err != nil {
		t.Fatalf("create permission for external peer: %v", err)
	}
	if _, err := aliceRelay.WriteTo([]byte("blocked"), peerConn.LocalAddr()); err != nil {
		t.Fatalf("external write unexpectedly failed: %v", err)
	}
	_ = peerConn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	readBuf := make([]byte, 256)
	if _, _, err := peerConn.ReadFromUDP(readBuf); !isTimeout(err) {
		t.Fatalf("expected internal-only relay to suppress external traffic, got %v", err)
	}
}

func TestInternalOnlyMappedAddressDoesNotBindHostPort(t *testing.T) {
	cfg := Config{
		Realm: "example.org",
		Listen: ListenConfig{
			RelayIP: "127.0.0.1",
		},
		Listeners: []TURNListenerConfig{
			{Type: "udp", Listen: "127.0.0.1:0"},
		},
		Users: []UserConfig{{
			Username:       "alice",
			Password:       "alice-pass",
			Port:           40122,
			MappedAddress:  "127.0.0.1:45122",
			SourceNetworks: []string{"127.0.0.0/8"},
			InternalOnly:   true,
		}},
	}
	server := newTestTURNServer(t, cfg)
	client := newTestTURNClient(t, server.listenAddr.String(), "alice", "alice-pass", "example.org")
	relayConn := allocateRelay(t, client)
	defer relayConn.Close()

	if got := relayConn.LocalAddr().String(); got != "127.0.0.1:45122" {
		t.Fatalf("unexpected mapped relay address %s", got)
	}
	hostProbe, err := net.ListenUDP("udp4", &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 45122,
	})
	if err != nil {
		t.Fatalf("expected internal-only mapped relay port to stay unbound on host: %v", err)
	}
	_ = hostProbe.Close()
}

func TestUserPortRangeSkipsOccupiedPort(t *testing.T) {
	occupied, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 40130})
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	cfg := Config{
		Realm: "example.org",
		Listen: ListenConfig{
			TurnListen: "127.0.0.1:0",
			RelayIP:    "127.0.0.1",
		},
		Users: []UserConfig{{
			Username:       "alice",
			Password:       "alice-pass",
			PortRangeStart: 40130,
			PortRangeEnd:   40132,
			SourceNetworks: []string{"127.0.0.0/8"},
		}},
	}
	server := newTestTURNServer(t, cfg)
	client := newTestTURNClient(t, server.listenAddr.String(), "alice", "alice-pass", "example.org")
	relayConn := allocateRelay(t, client)
	defer relayConn.Close()

	relayPort := relayConn.LocalAddr().(*net.UDPAddr).Port
	if relayPort < 40130 || relayPort > 40132 {
		t.Fatalf("unexpected relay port %d", relayPort)
	}
	if relayPort == 40130 {
		t.Fatalf("expected occupied port 40130 to be skipped")
	}
}

func Example_buildPionServer() {
	fmt.Println("buildPionServer constructs a Pion TURN server wrapper with open permission filtering.")
	// Output: buildPionServer constructs a Pion TURN server wrapper with open permission filtering.
}

func newTestTURNServer(t *testing.T, cfg Config) *openRelayPion {
	t.Helper()
	server, err := buildPionServer(cfg)
	if err != nil {
		t.Fatalf("buildPionServer: %v", err)
	}
	t.Cleanup(func() {
		if err := server.Close(); err != nil {
			t.Fatalf("close server: %v", err)
		}
	})
	return server
}

func newTestTURNClient(t *testing.T, serverAddr, username, password, realm string) *turn.Client {
	t.Helper()
	return newTestTURNClientWithTransportFromAddr(t, "udp", serverAddr, username, password, realm, nil, nil)
}

func newTestTURNClientWithTransport(t *testing.T, server *openRelayPion, listenerType, username, password, realm string) *turn.Client {
	t.Helper()
	addr := server.listenerAddrByType(listenerType)
	if addr == nil {
		t.Fatalf("listener type %q not found", listenerType)
	}
	return newTestTURNClientWithTransportFromAddr(t, listenerType, addr.String(), username, password, realm, nil, nil)
}

func newTestTURNClientWithTransportTLSOptions(t *testing.T, server *openRelayPion, listenerType, username, password, realm string, tlsCfg *tls.Config, dtlsCfg *piondtls.Config) *turn.Client {
	t.Helper()
	addr := server.listenerAddrByType(listenerType)
	if addr == nil {
		t.Fatalf("listener type %q not found", listenerType)
	}
	return newTestTURNClientWithTransportFromAddr(t, listenerType, addr.String(), username, password, realm, tlsCfg, dtlsCfg)
}

func newTestTURNClientWithTransportFromAddr(t *testing.T, listenerType, serverAddr, username, password, realm string, tlsCfg *tls.Config, dtlsCfg *piondtls.Config) *turn.Client {
	t.Helper()
	var (
		clientConn net.PacketConn
		err        error
	)
	switch listenerType {
	case "udp":
		clientConn, err = net.ListenPacket("udp4", "127.0.0.1:0")
	case "tcp":
		rawConn, dialErr := net.Dial("tcp", serverAddr)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		clientConn = turn.NewSTUNConn(rawConn)
	case "tls":
		if tlsCfg == nil {
			tlsCfg = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
		}
		rawConn, dialErr := tls.Dial("tcp", serverAddr, tlsCfg)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		clientConn = turn.NewSTUNConn(rawConn)
	case "dtls":
		udpAddr, resolveErr := net.ResolveUDPAddr("udp", serverAddr)
		if resolveErr != nil {
			t.Fatal(resolveErr)
		}
		if dtlsCfg == nil {
			dtlsCfg = &piondtls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			}
		}
		rawConn, dialErr := piondtls.Dial("udp", udpAddr, dtlsCfg)
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		clientConn = turn.NewSTUNConn(rawConn)
	default:
		t.Fatalf("unsupported listener type %q", listenerType)
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })

	client, err := turn.NewClient(&turn.ClientConfig{
		STUNServerAddr: serverAddr,
		TURNServerAddr: serverAddr,
		Conn:           clientConn,
		Username:       username,
		Password:       password,
		Realm:          realm,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	if err := client.Listen(); err != nil {
		t.Fatal(err)
	}
	return client
}

func allocateRelay(t *testing.T, client *turn.Client) net.PacketConn {
	t.Helper()
	relayConn, err := client.Allocate()
	if err != nil {
		t.Fatalf("allocate relay: %v", err)
	}
	return relayConn
}

func allocateRelayForTransport(t *testing.T, client *turn.Client, listenerType string) (net.Addr, func()) {
	t.Helper()
	switch listenerType {
	case "tcp", "tls":
		allocation, err := client.AllocateTCP()
		if err != nil {
			t.Fatalf("allocate tcp relay: %v", err)
		}
		return allocation.Addr(), func() { _ = allocation.Close() }
	default:
		relayConn := allocateRelay(t, client)
		return relayConn.LocalAddr(), func() { _ = relayConn.Close() }
	}
}

func udpEchoServer(conn *net.UDPConn) {
	buf := make([]byte, 2048)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		_, _ = conn.WriteToUDP(buf[:n], addr)
	}
}

func assertReadTimeout(t *testing.T, conn net.PacketConn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	if _, _, err := conn.ReadFrom(buf); !isTimeout(err) {
		t.Fatalf("expected read timeout, got %v", err)
	}
}

func isTimeout(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout() || errors.Is(err, os.ErrDeadlineExceeded)
}

func TestLoadConfigUserPortRangeRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "turn.yaml")
	cfgText := `realm: "example.org"
listen:
  relay_ip: "127.0.0.1"
listeners:
  - type: "udp"
    listen: "127.0.0.1:3478"
users:
  - username: "alice"
    password: "alice-pass"
    port_range_start: 45000
    port_range_end: 45005
    outbound_only: true
    internal_only: true
    source_networks:
      - "127.0.0.0/8"
`
	if err := os.WriteFile(cfgPath, []byte(cfgText), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Users) != 1 {
		t.Fatalf("unexpected user count %d", len(cfg.Users))
	}
	if cfg.Users[0].PortRangeStart != 45000 || cfg.Users[0].PortRangeEnd != 45005 {
		t.Fatalf("unexpected user port range %+v", cfg.Users[0])
	}
	if !cfg.Users[0].OutboundOnly || !cfg.Users[0].InternalOnly {
		t.Fatalf("expected outbound_only and internal_only to round-trip, got %+v", cfg.Users[0])
	}
	if len(cfg.Listeners) != 1 || cfg.Listeners[0].Type != "udp" || cfg.Listeners[0].Listen != "127.0.0.1:3478" {
		t.Fatalf("unexpected listeners %+v", cfg.Listeners)
	}
}
