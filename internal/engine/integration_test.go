// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	mrand "math/rand"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/proxy"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestEngineStarts(t *testing.T) {
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.10.1/32"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	eng := mustStart(t, cfg)
	if eng.Addr("socks5") == "" {
		t.Fatal("SOCKS5 listener did not start")
	}
}

func TestWireGuardHookScriptsRequireOptInAndRunInLifecycleOrder(t *testing.T) {
	key := mustKey(t)
	hookLog := filepath.Join(t.TempDir(), "wg-hooks.log")
	script := func(name string) string {
		if runtime.GOOS == "windows" {
			path := strings.ReplaceAll(hookLog, "'", "''")
			value := strings.ReplaceAll(name, "'", "''")
			return fmt.Sprintf("powershell -NoProfile -Command \"Add-Content -LiteralPath '%s' -Value '%s'\"", path, value)
		}
		return fmt.Sprintf("printf '%s\\n' >> %q", name, hookLog)
	}

	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.10.11/32"}
	cfg.WireGuard.PreUp = []string{script("preup")}
	cfg.WireGuard.PostUp = []string{script("postup")}
	cfg.WireGuard.PreDown = []string{script("predown")}
	cfg.WireGuard.PostDown = []string{script("postdown")}
	eng := mustStart(t, cfg)
	_ = eng.Close()

	if _, err := os.Stat(hookLog); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hook scripts ran even though scripts.allow is false: %v", err)
	}
	if runtime.GOOS == "windows" {
		return
	}

	cfg = config.Default()
	cfg.Scripts.Allow = true
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.10.12/32"}
	cfg.WireGuard.PreUp = []string{script("preup")}
	cfg.WireGuard.PostUp = []string{script("postup")}
	cfg.WireGuard.PreDown = []string{script("predown")}
	cfg.WireGuard.PostDown = []string{script("postdown")}
	eng = mustStart(t, cfg)
	_ = eng.Close()

	got, err := os.ReadFile(hookLog)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(got)) != "preup\npostup\npredown\npostdown" {
		t.Fatalf("unexpected hook order:\n%s", string(got))
	}
}

func TestTwoInstancesSOCKSHTTP(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	server := startHTTPServer(t)
	defer server.Close()

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	transparent := true
	serverCfg.Inbound.Transparent = &transparent
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.20.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.20.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.20.2/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{netip.PrefixFrom(hostIP, 32).String()},
		PersistentKeepalive: 1,
	}}
	clientCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	clientCfg.Proxy.HTTP = "127.0.0.1:0"
	httpUnix := filepath.Join(t.TempDir(), "http.sock")
	clientCfg.Proxy.HTTPListeners = []string{"unix:" + httpUnix}
	clientCfg.Forwards = []config.Forward{{Proto: "tcp", Listen: "127.0.0.1:0", Target: net.JoinHostPort(hostIP.String(), server.Port)}}
	clientEng := mustStart(t, clientCfg)

	sendMalformedWireGuard(t, serverPort)

	target := net.JoinHostPort(hostIP.String(), server.Port)
	body := socksHTTPGet(t, clientEng.Addr("socks5"), target)
	if body != "hello over wg" {
		t.Fatalf("unexpected body %q", body)
	}
	body = httpProxyGet(t, clientEng.Addr("http"), target)
	if body != "hello over wg" {
		t.Fatalf("unexpected HTTP proxy body %q", body)
	}
	body = httpProxyGetUnix(t, httpUnix, target)
	if body != "hello over wg" {
		t.Fatalf("unexpected Unix HTTP proxy body %q", body)
	}
	body = httpProxyConnectGet(t, clientEng.Addr("http"), target)
	if body != "hello over wg" {
		t.Fatalf("unexpected HTTP CONNECT body %q", body)
	}
	body = directHTTPGet(t, clientEng.Addr("forward.0"))
	if body != "hello over wg" {
		t.Fatalf("unexpected TCP forward body %q", body)
	}
	waitPeerStatus(t, clientEng, serverKey.PublicKey().String())
	waitPeerStatus(t, serverEng, clientKey.PublicKey().String())
}

func TestTransparentInboundICMPToHost(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	if !hostPingSupported(hostIP) {
		t.Skip("host unprivileged ICMP sockets are unavailable or not replying")
	}

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	transparent := true
	serverCfg.Inbound.Transparent = &transparent
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.20.11/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.20.12/32"},
	}}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.20.12/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{netip.PrefixFrom(hostIP, 32).String()},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	ping, err := clientEng.Ping(ctx, hostIP.String(), 1, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ping.Received != 1 {
		t.Fatalf("expected transparent ICMP reply, got %+v", ping)
	}
}

func TestForwardsReverseForwardsAndProxyProtocol(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)
	reverseIP := netip.MustParseAddr("100.64.51.99")
	proxySource := netip.MustParseAddrPort("203.0.113.9:4567")

	reverseTCP, reverseTCPHeader := startProxyProtocolTCPEchoServer(t)
	defer reverseTCP.Close()
	reverseUDP, reverseUDPHeader := startProxyProtocolUDPEchoServer(t)
	defer reverseUDP.Close()

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.51.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.51.2/32", "203.0.113.9/32"},
	}}
	serverCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	serverCfg.ReverseForwards = []config.Forward{
		{Proto: "tcp", Listen: netip.AddrPortFrom(reverseIP, 18080).String(), Target: reverseTCP.Addr().String(), ProxyProtocol: "v1"},
		{Proto: "udp", Listen: netip.AddrPortFrom(reverseIP, 18081).String(), Target: reverseUDP.LocalAddr().String(), ProxyProtocol: "v2"},
	}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	tunnelEcho, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.51.1:19090"))
	if err != nil {
		t.Fatal(err)
	}
	defer tunnelEcho.Close()
	remoteSeen := make(chan netip.AddrPort, 1)
	go func() {
		c, err := tunnelEcho.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		remoteSeen <- addrPortFromNetAddrTest(c.RemoteAddr())
		buf := make([]byte, len("normal-forward"))
		if _, err := io.ReadFull(c, buf); err == nil {
			_, _ = c.Write(buf)
		}
	}()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.51.2/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.51.1/32", netip.PrefixFrom(reverseIP, 32).String()},
		PersistentKeepalive: 1,
	}}
	clientCfg.Forwards = []config.Forward{{Proto: "tcp", Listen: "127.0.0.1:0", Target: "100.64.51.1:19090", ProxyProtocol: "v1"}}
	clientEng := mustStart(t, clientCfg)
	defer clientEng.Close()

	local, err := net.DialTimeout("tcp", clientEng.Addr("forward.0"), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = local.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(local, "PROXY TCP4 %s 100.64.51.1 %d 19090\r\nnormal-forward", proxySource.Addr(), proxySource.Port()); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("normal-forward"))
	if _, err := io.ReadFull(local, buf); err != nil {
		t.Fatal(err)
	}
	_ = local.Close()
	if !bytes.Equal(buf, []byte("normal-forward")) {
		t.Fatalf("normal forward payload was not echoed cleanly: %q", buf)
	}
	select {
	case got := <-remoteSeen:
		if got != proxySource {
			t.Fatalf("PROXY source was not preserved over tunnel: got %s want %s", got, proxySource)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not observe normal forwarded connection")
	}

	conn := retryEngineDial(t, clientEng, "tcp", netip.AddrPortFrom(reverseIP, 18080).String())
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("reverse-tcp")); err != nil {
		t.Fatal(err)
	}
	buf = make([]byte, len("reverse-tcp"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if !bytes.Equal(buf, []byte("reverse-tcp")) {
		t.Fatalf("reverse TCP payload mismatch: got %q", buf)
	}
	select {
	case header := <-reverseTCPHeader:
		if !strings.HasPrefix(header, "PROXY TCP4 100.64.51.2 100.64.51.99 ") {
			t.Fatalf("unexpected reverse TCP PROXY header %q", header)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reverse TCP target did not receive PROXY header")
	}

	got := socksEcho(t, serverEng.Addr("socks5"), netip.AddrPortFrom(reverseIP, 18080).String(), []byte("socks-to-reverse"))
	if !bytes.Equal(got, []byte("socks-to-reverse")) {
		t.Fatalf("SOCKS-to-reverse payload mismatch: got %q", got)
	}
	select {
	case header := <-reverseTCPHeader:
		if !strings.HasPrefix(header, "PROXY TCP4 127.0.0.1 100.64.51.99 ") {
			t.Fatalf("unexpected SOCKS-to-reverse PROXY header %q", header)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reverse TCP target did not receive SOCKS-to-reverse PROXY header")
	}

	uconn, err := clientEng.DialUDP(netip.AddrPort{}, netip.AddrPortFrom(reverseIP, 18081))
	if err != nil {
		t.Fatal(err)
	}
	defer uconn.Close()
	udpRoundTrip(t, uconn, []byte("reverse-udp"))
	select {
	case header := <-reverseUDPHeader:
		if !strings.HasPrefix(header, "100.64.51.2:") || !strings.HasSuffix(header, ">100.64.51.99:18081") {
			t.Fatalf("unexpected reverse UDP PROXY header %q", header)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reverse UDP target did not receive PROXY header")
	}
}

func TestSOCKSHostnameUsesWireGuardDNS(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.25.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.25.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	echo, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.25.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer echo.Close()
	go serveEchoListener(echo)

	dnsUDP, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.25.1:53"))
	if err != nil {
		t.Fatal(err)
	}
	defer dnsUDP.Close()
	go serveStaticTunnelDNS(dnsUDP, map[string]netip.Addr{"only-tunnel.invalid.": netip.MustParseAddr("100.64.25.1")})

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.25.2/32"}
	clientCfg.WireGuard.DNS = []string{"100.64.25.1"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.25.1/32"},
		PersistentKeepalive: 1,
	}}
	clientCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	clientEng := mustStart(t, clientCfg)

	msg := []byte("resolved-over-wireguard-dns")
	got := socksEcho(t, clientEng.Addr("socks5"), "only-tunnel.invalid:18080", msg)
	if !bytes.Equal(msg, got) {
		t.Fatalf("SOCKS hostname echo mismatch: got %q", got)
	}
}

func TestTunnelUDPAndSOCKSUDPAssociateBindAndAPIPing(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.26.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.26.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	udpEcho, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.26.1:19000"))
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	socksUDPSource := make(chan net.Addr, 1)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := udpEcho.ReadFrom(buf)
			if err != nil {
				return
			}
			if bytes.Equal(buf[:n], []byte("socks-udp")) {
				select {
				case socksUDPSource <- addr:
				default:
				}
			}
			_, _ = udpEcho.WriteTo(buf[:n], addr)
		}
	}()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.26.2/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.26.1/32"},
		PersistentKeepalive: 1,
	}}
	clientCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	var occupiedRelay net.PacketConn
	var occupiedRelayPort int
	for i := 0; i < 64; i++ {
		candidate, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := candidate.LocalAddr().(*net.UDPAddr).Port
		if port <= 65515 {
			occupiedRelay = candidate
			occupiedRelayPort = port
			break
		}
		candidate.Close()
	}
	if occupiedRelay == nil {
		t.Fatal("failed to reserve UDP relay port with range headroom")
	}
	defer occupiedRelay.Close()
	clientCfg.Proxy.UDPAssociatePorts = fmt.Sprintf("%d-%d", occupiedRelayPort, occupiedRelayPort+20)
	clientCfg.Inbound.UDPIdleTimeoutSeconds = 1
	bind := true
	clientCfg.Proxy.Bind = &bind
	clientCfg.API.Listen = "127.0.0.1:0"
	clientCfg.API.Token = "secret"
	clientCfg.Forwards = []config.Forward{{Proto: "udp", Listen: "127.0.0.1:0", Target: "100.64.26.1:19000"}}
	clientEng := mustStart(t, clientCfg)

	conn, err := clientEng.DialUDP(netip.AddrPort{}, netip.MustParseAddrPort("100.64.26.1:19000"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	udpRoundTrip(t, conn, []byte("library-udp"))

	if runtime.GOOS != "windows" {
		udp, relay := socksUDPAssociateRelay(t, clientEng.Addr("socks5"))
		defer udp.Close()
		if got := int(relay.Port()); got < occupiedRelayPort || got > occupiedRelayPort+20 {
			t.Fatalf("SOCKS UDP relay port %d outside configured range %d-%d", got, occupiedRelayPort, occupiedRelayPort+20)
		}
		if got := int(relay.Port()); got == occupiedRelayPort {
			t.Fatalf("SOCKS UDP relay reused occupied port %d", got)
		}
		if _, err := udp.Write(socksUDPDatagram(t, netip.MustParseAddrPort("100.64.26.1:19000"), []byte("socks-udp"))); err != nil {
			t.Fatal(err)
		}
		got := readSOCKSUDPDatagram(t, udp)
		if !bytes.Equal(got, []byte("socks-udp")) {
			t.Fatalf("SOCKS UDP echo mismatch: got %q", got)
		}
		var socksRemote net.Addr
		select {
		case socksRemote = <-socksUDPSource:
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for SOCKS UDP source")
		}
		time.Sleep(1200 * time.Millisecond)
		if _, err := udpEcho.WriteTo([]byte("socks-late"), socksRemote); err != nil {
			t.Fatal(err)
		}
		_ = udp.SetDeadline(time.Now().Add(300 * time.Millisecond))
		late := make([]byte, 64)
		if n, err := udp.Read(late); err == nil {
			t.Fatalf("SOCKS UDP delivered expired peer datagram %q", late[:n])
		}
	}

	forwardUDP, err := net.Dial("udp", clientEng.Addr("forward.0"))
	if err != nil {
		t.Fatal(err)
	}
	defer forwardUDP.Close()
	udpRoundTrip(t, forwardUDP, []byte("forward-udp"))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ping, err := clientEng.Ping(ctx, "100.64.26.1", 2, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ping.Received == 0 {
		t.Fatalf("expected ping replies, got %+v", ping)
	}
	resp, body := apiRequest(t, clientEng.Addr("api"), "secret", http.MethodGet, "/v1/ping?target=100.64.26.1&count=1&timeout_ms=1000", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("API ping status %d: %s", resp.StatusCode, body)
	}
	var apiPing engine.PingResult
	if err := json.Unmarshal([]byte(body), &apiPing); err != nil {
		t.Fatalf("decode API ping: %v: %s", err, body)
	}
	if apiPing.Received == 0 {
		t.Fatalf("expected API ping reply, got %+v", apiPing)
	}

	bound, bindDone := socksBind(t, clientEng.Addr("socks5"), netip.MustParseAddrPort("0.0.0.0:0"))
	incoming := retryEngineDial(t, serverEng, "tcp", bound.String())
	defer incoming.Close()
	_ = incoming.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := incoming.Write([]byte("bind-ok")); err != nil {
		t.Fatal(err)
	}
	gotBind := make([]byte, len("bind-ok"))
	if _, err := io.ReadFull(incoming, gotBind); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotBind, []byte("bind-ok")) {
		t.Fatalf("SOCKS BIND echo mismatch: got %q", gotBind)
	}
	if err := <-bindDone; err != nil {
		t.Fatal(err)
	}
}

func TestIPv6TunnelTrafficAndIPv6OuterEndpoint(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDP6Port(t)
	serverAddr := netip.MustParseAddr("fd7a:115c:a1e0::1")
	clientAddr := netip.MustParseAddr("fd7a:115c:a1e0::2")

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{serverAddr.String() + "/128"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{clientAddr.String() + "/128"},
	}}
	serverEng := mustStart(t, serverCfg)

	tcpEcho, err := serverEng.ListenTCP(netip.AddrPortFrom(serverAddr, 19080))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpEcho.Close()
	go serveEchoListener(tcpEcho)
	udpEcho, err := serverEng.ListenUDP(netip.AddrPortFrom(serverAddr, 19081))
	if err != nil {
		t.Fatal(err)
	}
	defer udpEcho.Close()
	go serveUDPEcho(udpEcho)

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{clientAddr.String() + "/128"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("[::1]:%d", serverPort),
		AllowedIPs:          []string{serverAddr.String() + "/128"},
		PersistentKeepalive: 1,
	}}
	clientCfg.Proxy.SOCKS5 = "[::1]:0"
	clientEng := mustStart(t, clientCfg)

	got := socksEcho(t, clientEng.Addr("socks5"), net.JoinHostPort(serverAddr.String(), "19080"), []byte("ipv6-tcp"))
	if !bytes.Equal(got, []byte("ipv6-tcp")) {
		t.Fatalf("IPv6 SOCKS echo mismatch: got %q", got)
	}
	uconn, err := clientEng.DialUDP(netip.AddrPort{}, netip.AddrPortFrom(serverAddr, 19081))
	if err != nil {
		t.Fatal(err)
	}
	defer uconn.Close()
	udpRoundTrip(t, uconn, []byte("ipv6-udp"))
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	ping, err := clientEng.Ping(ctx, serverAddr.String(), 1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if ping.Received != 1 {
		t.Fatalf("expected IPv6 ICMP reply, got %+v", ping)
	}
	waitPeerStatus(t, clientEng, serverKey.PublicKey().String())
	waitPeerStatus(t, serverEng, clientKey.PublicKey().String())
}

func TestSOCKSFailureIsReported(t *testing.T) {
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.27.1/32"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	fallback := false
	cfg.Proxy.FallbackDirect = &fallback
	eng := mustStart(t, cfg)

	rep := socksConnectReply(t, eng.Addr("socks5"), netip.MustParseAddrPort("192.0.2.1:443"))
	if rep == 0 {
		t.Fatal("SOCKS CONNECT unexpectedly succeeded for unroutable destination with fallback disabled")
	}
}

func TestOutboundProxyListForSOCKSAndInboundTransparent(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	echo := startEchoServer(t)
	defer echo.Close()
	httpProxy, proxyTargets := startHTTPConnectProxy(t)
	defer httpProxy.Close()
	honorEnv := false
	fallbackDirect := false

	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.34.1/32"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	cfg.Proxy.HonorEnvironment = &honorEnv
	cfg.Proxy.FallbackDirect = &fallbackDirect
	cfg.Proxy.OutboundProxies = []config.OutboundProxy{{
		Type:    "http",
		Address: httpProxy.Addr().String(),
		Roles:   []string{"socks"},
		Subnets: []string{netip.PrefixFrom(hostIP, 32).String()},
	}}
	eng := mustStart(t, cfg)

	target := net.JoinHostPort(hostIP.String(), echo.Port)
	got := socksEcho(t, eng.Addr("socks5"), target, []byte("socks-http-connect"))
	if !bytes.Equal(got, []byte("socks-http-connect")) {
		t.Fatalf("SOCKS outbound proxy echo mismatch: got %q", got)
	}
	select {
	case gotTarget := <-proxyTargets:
		if gotTarget != target {
			t.Fatalf("HTTP outbound proxy saw target %q, want %q", gotTarget, target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP outbound proxy was not used for SOCKS fallback")
	}

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)
	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	transparent := true
	serverCfg.Inbound.Transparent = &transparent
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.34.10/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.34.11/32"},
	}}
	serverCfg.Proxy.HonorEnvironment = &honorEnv
	serverCfg.Proxy.OutboundProxies = []config.OutboundProxy{{
		Type:    "http",
		Address: httpProxy.Addr().String(),
		Roles:   []string{"inbound"},
		Subnets: []string{netip.PrefixFrom(hostIP, 32).String()},
	}}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.34.11/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{netip.PrefixFrom(hostIP, 32).String()},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)

	echoOverEngine(t, clientEng, target, []byte("inbound-http-connect"))
	select {
	case gotTarget := <-proxyTargets:
		if gotTarget != target {
			t.Fatalf("HTTP inbound proxy saw target %q, want %q", gotTarget, target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("HTTP outbound proxy was not used for inbound transparent forwarding")
	}
}

func TestOutboundSOCKS5ProxyUDP(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	hostUDP, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hostUDP.Close()
	go serveUDPEcho(hostUDP)
	_, udpPort, err := net.SplitHostPort(hostUDP.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}

	honorEnv := false
	upstreamKey := mustKey(t)
	upstreamCfg := config.Default()
	upstreamCfg.WireGuard.PrivateKey = upstreamKey.String()
	upstreamCfg.WireGuard.Addresses = []string{"100.64.35.1/32"}
	upstreamCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	upstreamCfg.Proxy.HonorEnvironment = &honorEnv
	upstream := mustStart(t, upstreamCfg)

	fallbackDirect := false
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.35.2/32"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	cfg.Proxy.HonorEnvironment = &honorEnv
	cfg.Proxy.FallbackDirect = &fallbackDirect
	cfg.Proxy.OutboundProxies = []config.OutboundProxy{{
		Type:    "socks5",
		Address: upstream.Addr("socks5"),
		Roles:   []string{"socks"},
		Subnets: []string{netip.PrefixFrom(hostIP, 32).String()},
	}}
	eng := mustStart(t, cfg)

	udp := socksUDPAssociate(t, eng.Addr("socks5"))
	defer udp.Close()
	target := netip.MustParseAddrPort(net.JoinHostPort(hostIP.String(), udpPort))
	if _, err := udp.Write(socksUDPDatagram(t, target, []byte("udp-via-socks5-fallback"))); err != nil {
		t.Fatal(err)
	}
	got := readSOCKSUDPDatagram(t, udp)
	if !bytes.Equal(got, []byte("udp-via-socks5-fallback")) {
		t.Fatalf("SOCKS5 outbound UDP proxy echo mismatch: got %q", got)
	}
}

func TestSOCKSAuthHostForwardVirtualSubnetAndReservedAddresses(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()
	httpServer := startHTTPServer(t)
	defer httpServer.Close()

	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.29.1/32", "10.10.10.2/24"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	cfg.Proxy.HTTP = "127.0.0.1:0"
	cfg.Proxy.Username = "alice"
	cfg.Proxy.Password = "secret"
	eng := mustStart(t, cfg)

	c, err := net.DialTimeout("tcp", eng.Addr("socks5"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(c, method[:]); err != nil {
		t.Fatal(err)
	}
	if method != [2]byte{0x05, 0xff} {
		t.Fatalf("SOCKS without auth was not rejected: %v", method)
	}
	_ = c.Close()

	authConn := socksControlAuth(t, eng.Addr("socks5"), "alice", "secret")
	if _, err := authConn.Write(socksRequestBytes(0x01, netip.MustParseAddrPort("100.64.29.1:"+echo.Port))); err != nil {
		t.Fatal(err)
	}
	rep, _ := readSOCKSReply(t, authConn)
	if rep != 0 {
		t.Fatalf("host-forwarded SOCKS CONNECT failed with reply %d", rep)
	}
	msg := []byte("host-forward")
	if _, err := authConn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(authConn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("host-forward echo mismatch: got %q", got)
	}
	_ = authConn.Close()

	req, err := http.NewRequest(http.MethodGet, "http://100.64.29.1:"+httpServer.Port+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, _ := url.Parse("http://" + eng.Addr("http"))
	httpClient := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}
	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("HTTP proxy without auth status=%d", resp.StatusCode)
	}
	_ = resp.Body.Close()

	req, err = http.NewRequest(http.MethodGet, "http://100.64.29.1:"+httpServer.Port+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:secret")))
	resp, err = httpClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "hello over wg" {
		t.Fatalf("unexpected authenticated HTTP proxy response status=%d body=%q", resp.StatusCode, body)
	}

	rep = socksConnectReplyAuth(t, eng.Addr("socks5"), "alice", "secret", netip.MustParseAddrPort("10.10.10.99:1"))
	if rep == 0 {
		t.Fatal("virtual Address subnet destination fell back instead of being rejected")
	}
	rep = socksConnectReplyAuth(t, eng.Addr("socks5"), "alice", "secret", netip.MustParseAddrPort("224.0.0.1:1"))
	if rep == 0 {
		t.Fatal("reserved IPv4 destination was not rejected")
	}
}

func TestHTTPProxyAbsoluteFormHTTPS(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello over https proxy")
	}))
	defer upstream.Close()

	caFile := filepath.Join(t.TempDir(), "https-proxy-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: upstream.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}

	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.29.2/32"}
	cfg.Proxy.HTTP = "127.0.0.1:0"
	cfg.Proxy.HTTPSProxyVerify = "ca"
	cfg.Proxy.HTTPSProxyCAFile = caFile
	eng := mustStart(t, cfg)

	status, body := httpProxyAbsoluteFormGet(t, eng.Addr("http"), upstream.URL)
	if status != http.StatusOK || body != "hello over https proxy" {
		t.Fatalf("unexpected HTTPS proxy response status=%d body=%q", status, body)
	}
}

func TestHTTPProxyAbsoluteFormHTTPSCanBeDisabled(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "should not be reached")
	}))
	defer upstream.Close()

	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.29.3/32"}
	cfg.Proxy.HTTP = "127.0.0.1:0"
	enabled := false
	cfg.Proxy.HTTPSProxying = &enabled
	eng := mustStart(t, cfg)

	status, _ := httpProxyAbsoluteFormGet(t, eng.Addr("http"), upstream.URL)
	if status != http.StatusForbidden {
		t.Fatalf("unexpected disabled HTTPS proxy status=%d", status)
	}
}

func TestBINDDefaultDisabled(t *testing.T) {
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.31.1/32"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	eng := mustStart(t, cfg)

	control := socksControl(t, eng.Addr("socks5"))
	defer control.Close()
	if _, err := control.Write(socksRequestBytes(0x02, netip.MustParseAddrPort("100.64.31.1:0"))); err != nil {
		t.Fatal(err)
	}
	rep, _ := readSOCKSReply(t, control)
	if rep != 0x07 {
		t.Fatalf("BIND should be disabled by default, got SOCKS reply %d", rep)
	}
}

func TestSOCKSUDPAssociatePinsClientEndpoint(t *testing.T) {
	hostUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hostUDP.Close()
	go serveUDPEcho(hostUDP)

	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.31.2/32"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	eng := mustStart(t, cfg)

	udp, relay := socksUDPAssociateRelay(t, eng.Addr("socks5"))
	defer udp.Close()
	target := netip.MustParseAddrPort(hostUDP.LocalAddr().String())
	if _, err := udp.Write(socksUDPDatagram(t, target, []byte("primary"))); err != nil {
		t.Fatal(err)
	}
	if got := readSOCKSUDPDatagram(t, udp); !bytes.Equal(got, []byte("primary")) {
		t.Fatalf("primary UDP associate echo mismatch: got %q", got)
	}

	intruder, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(relay))
	if err != nil {
		t.Fatal(err)
	}
	defer intruder.Close()
	_ = intruder.SetDeadline(time.Now().Add(300 * time.Millisecond))
	if _, err := intruder.Write(socksUDPDatagram(t, target, []byte("intruder"))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 256)
	if _, err := intruder.Read(buf); err == nil {
		t.Fatal("intruder UDP endpoint unexpectedly received a response")
	} else if nerr, ok := err.(net.Error); !ok || !nerr.Timeout() {
		t.Fatalf("intruder UDP read error = %v, want timeout", err)
	}

	if _, err := udp.Write(socksUDPDatagram(t, target, []byte("primary-again"))); err != nil {
		t.Fatal(err)
	}
	if got := readSOCKSUDPDatagram(t, udp); !bytes.Equal(got, []byte("primary-again")) {
		t.Fatalf("post-intruder UDP associate echo mismatch: got %q", got)
	}
}

func TestForwardListenFailureIsReported(t *testing.T) {
	key := mustKey(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()

	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.31.10/32"}
	cfg.Forwards = []config.Forward{{Proto: "tcp", Listen: occupied.Addr().String(), Target: "100.64.31.11:80"}}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(cfg, log.New(testLogWriter{t: t}, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	err = eng.Start()
	_ = eng.Close()
	if err == nil {
		t.Fatal("engine started even though a forward listen address was already in use")
	}
}

func TestReverseForwardListenFailureIsReported(t *testing.T) {
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.31.20/32"}
	cfg.ReverseForwards = []config.Forward{
		{Proto: "tcp", Listen: "100.64.31.20:18080", Target: "127.0.0.1:1"},
		{Proto: "tcp", Listen: "100.64.31.20:18080", Target: "127.0.0.1:1"},
	}
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(cfg, log.New(testLogWriter{t: t}, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	err = eng.Start()
	_ = eng.Close()
	if err == nil {
		t.Fatal("engine started even though two reverse forwards used the same tunnel listen address")
	}
}

func TestInboundHostForwardRequiresExplicitEnable(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	transparent := true
	serverCfg.Inbound.Transparent = &transparent
	enabled := true
	serverCfg.HostForward.Inbound.Enabled = &enabled
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.32.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.32.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.32.2/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.32.1/32", "127.0.0.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)

	echoOverEngine(t, clientEng, "100.64.32.1:"+echo.Port, []byte("inbound-host"))

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	if conn, err := clientEng.DialTunnelContext(ctx, "tcp", "127.0.0.1:"+echo.Port); err == nil {
		conn.Close()
		t.Fatal("WireGuard packet to 127.0.0.0/8 unexpectedly reached host loopback")
	}
}

func TestFirstWireGuardAddressIsPrimarySource(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.33.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.33.2/32", "100.64.33.22/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.33.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	remote := make(chan netip.Addr, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		remote <- addrPortFromNetAddrTest(c.RemoteAddr()).Addr()
	}()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.33.2/32", "100.64.33.22/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.33.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)
	conn := retryEngineDial(t, clientEng, "tcp", "100.64.33.1:18080")
	_ = conn.Close()

	select {
	case got := <-remote:
		if want := netip.MustParseAddr("100.64.33.2"); got != want {
			t.Fatalf("primary source address mismatch: got %s want %s", got, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not observe inbound TCP connection")
	}
}

func TestClientSurvivesServerRestartAfterPeerRefresh(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)
	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.28.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.28.2/32"},
	}}
	startServer := func() *engine.Engine {
		eng := mustStart(t, serverCfg)
		ln, err := eng.ListenTCP(netip.MustParseAddrPort("100.64.28.1:18080"))
		if err != nil {
			t.Fatal(err)
		}
		go serveEchoListener(ln)
		t.Cleanup(func() { _ = ln.Close() })
		return eng
	}
	serverEng := startServer()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.28.2/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.28.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)
	echoOverEngine(t, clientEng, "100.64.28.1:18080", []byte("before-restart"))

	_ = serverEng.Close()
	time.Sleep(100 * time.Millisecond)
	serverEng = startServer()
	if err := clientEng.RemovePeer(clientCfg.WireGuard.Peers[0].PublicKey); err != nil {
		t.Fatal(err)
	}
	if err := clientEng.AddPeer(clientCfg.WireGuard.Peers[0]); err != nil {
		t.Fatal(err)
	}
	echoOverEngine(t, clientEng, "100.64.28.1:18080", []byte("after-restart"))
	waitPeerStatus(t, serverEng, clientKey.PublicKey().String())
}

func TestPacketLossTransfer(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	echo := startEchoServer(t)
	defer echo.Close()

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)
	lossyPort, closeProxy := startLossyUDPProxy(t, serverPort, 0.01)
	defer closeProxy()

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	transparent := true
	serverCfg.Inbound.Transparent = &transparent
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.30.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.30.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.30.2/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", lossyPort),
		AllowedIPs:          []string{netip.PrefixFrom(hostIP, 32).String()},
		PersistentKeepalive: 1,
	}}
	clientCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	clientEng := mustStart(t, clientCfg)

	dialer, err := proxy.SOCKS5("tcp", clientEng.Addr("socks5"), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn := retryDial(t, dialer, net.JoinHostPort(hostIP.String(), echo.Port))
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	payload := make([]byte, 3*1024*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		errc <- err
	}()
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if err := <-errc; err != nil {
		t.Fatalf("write payload: %v", err)
	}
	if !bytes.Equal(payload, got) {
		t.Fatal("echo payload mismatch under packet loss")
	}
}

func TestMultiPeer(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	echo := startEchoServer(t)
	defer echo.Close()

	serverKey, c1Key, c2Key := mustKey(t), mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)
	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	transparent := true
	serverCfg.Inbound.Transparent = &transparent
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.40.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{
		{PublicKey: c1Key.PublicKey().String(), AllowedIPs: []string{"100.64.40.2/32"}},
		{PublicKey: c2Key.PublicKey().String(), AllowedIPs: []string{"100.64.40.3/32"}},
	}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	for i, key := range []wgtypes.Key{c1Key, c2Key} {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = key.String()
		cfg.WireGuard.Addresses = []string{fmt.Sprintf("100.64.40.%d/32", i+2)}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           serverKey.PublicKey().String(),
			Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
			AllowedIPs:          []string{netip.PrefixFrom(hostIP, 32).String()},
			PersistentKeepalive: 1,
		}}
		cfg.Proxy.SOCKS5 = "127.0.0.1:0"
		client := mustStart(t, cfg)
		msg := []byte(fmt.Sprintf("client-%d", i+1))
		got := socksEcho(t, client.Addr("socks5"), net.JoinHostPort(hostIP.String(), echo.Port), msg)
		if !bytes.Equal(msg, got) {
			t.Fatalf("client %d echo mismatch: got %q", i+1, got)
		}
		client.Close()
	}
}

func TestAPIServerPeerAndACL(t *testing.T) {
	serverKey, peerKey := mustKey(t), mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = serverKey.String()
	cfg.WireGuard.Addresses = []string{"100.64.45.1/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "secret"
	eng := mustStart(t, cfg)

	resp, body := apiRequest(t, eng.Addr("api"), "", http.MethodGet, "/v1/peers", nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized API request, got %d: %s", resp.StatusCode, body)
	}

	peerBody := map[string]any{
		"public_key":  peerKey.PublicKey().String(),
		"allowed_ips": []string{"100.64.45.2/32"},
		"traffic_shaper": map[string]any{
			"upload_bps":   1500000,
			"download_bps": 2500000,
			"latency_ms":   12,
		},
	}
	resp, body = apiRequest(t, eng.Addr("api"), "secret", http.MethodPost, "/v1/peers", peerBody)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("add peer status %d: %s", resp.StatusCode, body)
	}
	if len(eng.Peers()) != 1 {
		t.Fatalf("expected one peer after API add, got %d", len(eng.Peers()))
	}
	if got := eng.Peers()[0].TrafficShaper; got.UploadBps != 1500000 || got.DownloadBps != 2500000 || got.LatencyMillis != 12 {
		t.Fatalf("peer shaper was not applied through API add: %+v", got)
	}
	peerBody["traffic_shaper"] = map[string]any{
		"upload_bps":   3500000,
		"download_bps": 4500000,
		"latency_ms":   30,
	}
	resp, body = apiRequest(t, eng.Addr("api"), "secret", http.MethodPut, "/v1/peers", peerBody)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("replace peer shaper status %d: %s", resp.StatusCode, body)
	}
	if got := eng.Peers()[0].TrafficShaper; got.UploadBps != 3500000 || got.DownloadBps != 4500000 || got.LatencyMillis != 30 {
		t.Fatalf("peer shaper was not replaced live through API: %+v", got)
	}
	resp, body = apiRequest(t, eng.Addr("api"), "secret", http.MethodGet, "/v1/peers/"+url.PathEscape(peerKey.PublicKey().String()), nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get peer by path status %d: %s", resp.StatusCode, body)
	}
	resp, body = apiRequest(t, eng.Addr("api"), "secret", http.MethodGet, "/v1/status", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status endpoint status %d: %s", resp.StatusCode, body)
	}
	var apiStatus engine.Status
	if err := json.Unmarshal([]byte(body), &apiStatus); err != nil {
		t.Fatalf("decode status response: %v: %s", err, body)
	}
	if len(apiStatus.Peers) != 1 || apiStatus.Peers[0].PublicKey != peerKey.PublicKey().String() {
		t.Fatalf("unexpected status peers: %+v", apiStatus.Peers)
	}
	if apiStatus.Peers[0].HasHandshake {
		t.Fatalf("fresh API-added peer should not report a handshake yet: %+v", apiStatus.Peers[0])
	}
	libraryStatus, err := eng.Status()
	if err != nil {
		t.Fatal(err)
	}
	if libraryStatus.ActiveConnections != apiStatus.ActiveConnections {
		t.Fatalf("library/API status mismatch: library=%+v api=%+v", libraryStatus, apiStatus)
	}

	aclBody := map[string]any{
		"inbound_default":  "allow",
		"outbound_default": "deny",
		"relay_default":    "deny",
		"outbound": []map[string]any{{
			"action":      "allow",
			"destination": "100.64.45.0/24",
		}},
	}
	resp, body = apiRequest(t, eng.Addr("api"), "secret", http.MethodPut, "/v1/acls", aclBody)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("set ACL status %d: %s", resp.StatusCode, body)
	}
	gotACL := eng.ACL()
	if gotACL.OutboundDefault != acl.Deny || len(gotACL.Outbound) != 1 {
		t.Fatalf("ACL was not updated: %+v", gotACL)
	}
	resp, body = apiRequest(t, eng.Addr("api"), "secret", http.MethodPost, "/v1/acls/outbound", map[string]any{
		"action":      "allow",
		"destination": "100.64.46.0/24",
	})
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("append outbound ACL status %d: %s", resp.StatusCode, body)
	}
	if got := eng.ACL(); len(got.Outbound) != 2 {
		t.Fatalf("expected appended outbound ACL rule, got %+v", got.Outbound)
	}
	resp, body = apiRequest(t, eng.Addr("api"), "secret", http.MethodDelete, "/v1/acls/outbound?index=1", nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete outbound ACL status %d: %s", resp.StatusCode, body)
	}
	if got := eng.ACL(); len(got.Outbound) != 1 {
		t.Fatalf("expected one outbound ACL rule after delete, got %+v", got.Outbound)
	}

	path := "/v1/peers?public_key=" + url.QueryEscape(peerKey.PublicKey().String())
	resp, body = apiRequest(t, eng.Addr("api"), "secret", http.MethodDelete, path, nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete peer status %d: %s", resp.StatusCode, body)
	}
	if len(eng.Peers()) != 0 {
		t.Fatalf("expected no peers after API delete, got %d", len(eng.Peers()))
	}

	scriptPath := t.TempDir() + "/should-not-exist"
	replacementPeer := mustKey(t)
	wgText := fmt.Sprintf(`[Interface]
PrivateKey = %s
PreUp = touch %s
PostUp = touch %s
PreDown = touch %s
PostDown = touch %s

[Peer]
PublicKey = %s
AllowedIPs = 100.64.45.9/32
PersistentKeepalive = 7
`, serverKey.String(), scriptPath, scriptPath, scriptPath, scriptPath, replacementPeer.PublicKey().String())
	resp, body = apiRawRequest(t, eng.Addr("api"), "secret", http.MethodPut, "/v1/wireguard/config", "text/plain", []byte(wgText))
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("wireguard config replace status %d: %s", resp.StatusCode, body)
	}
	if _, err := os.Stat(scriptPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("runtime WireGuard config API executed scripts; stat err=%v", err)
	}
	peers := eng.Peers()
	if len(peers) != 1 || peers[0].PublicKey != replacementPeer.PublicKey().String() || peers[0].PersistentKeepalive != 7 {
		t.Fatalf("runtime WireGuard config did not replace peers safely: %+v", peers)
	}
	wgTextWithAddress := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = 100.64.45.99/32

[Peer]
PublicKey = %s
AllowedIPs = 100.64.45.9/32
`, serverKey.String(), replacementPeer.PublicKey().String())
	resp, body = apiRawRequest(t, eng.Addr("api"), "secret", http.MethodPut, "/v1/wireguard/config", "text/plain", []byte(wgTextWithAddress))
	if resp.StatusCode == http.StatusNoContent {
		t.Fatal("runtime WireGuard config accepted an Address= change that requires netstack rebuild")
	}
	resp, body = apiRequest(t, eng.Addr("api"), "secret", http.MethodGet, "/v1/interface_ips", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("interface IPs status %d: %s", resp.StatusCode, body)
	}
	var ips []string
	if err := json.Unmarshal([]byte(body), &ips); err != nil {
		t.Fatalf("decode interface IPs: %v: %s", err, body)
	}
	if len(ips) != 1 || ips[0] != "100.64.45.1" {
		t.Fatalf("unexpected interface IPs: %v", ips)
	}
}

func TestAPIUnixSocketCanOptOutOfToken(t *testing.T) {
	key := mustKey(t)
	socketPath := t.TempDir() + "/uwg-api.sock"
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.45.10/32"}
	cfg.API.Listen = "unix:" + socketPath
	cfg.API.AllowUnauthenticatedUnix = true
	eng := mustStart(t, cfg)

	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketPath)
		}},
	}
	resp, err := client.Get("http://uwg/v1/status")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("unix API status %d: %s", resp.StatusCode, body)
	}
	if eng.Addr("api") != socketPath {
		t.Fatalf("API unix addr mismatch: got %q want %q", eng.Addr("api"), socketPath)
	}
}

func TestAPIAddsAndDeletesReverseForward(t *testing.T) {
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.45.20/32"}
	cfg.API.Listen = "127.0.0.1:0"
	cfg.API.Token = "secret"
	eng := mustStart(t, cfg)

	body := map[string]any{
		"reverse":        true,
		"proto":          "tcp",
		"listen":         "100.64.45.20:18080",
		"target":         "127.0.0.1:1",
		"proxy_protocol": "v1",
	}
	resp, text := apiRequest(t, eng.Addr("api"), "secret", http.MethodPost, "/v1/forwards", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add reverse forward status %d: %s", resp.StatusCode, text)
	}
	var created map[string]any
	if err := json.Unmarshal([]byte(text), &created); err != nil {
		t.Fatalf("decode forward response: %v: %s", err, text)
	}
	name, _ := created["name"].(string)
	if name == "" || eng.Addr(name) == "" {
		t.Fatalf("reverse forward was not registered: name=%q addr=%q body=%s", name, eng.Addr(name), text)
	}
	resp, text = apiRequest(t, eng.Addr("api"), "secret", http.MethodDelete, "/v1/forwards?name="+url.QueryEscape(name), nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete reverse forward status %d: %s", resp.StatusCode, text)
	}
	if eng.Addr(name) != "" {
		t.Fatalf("reverse forward %s still has an address after delete: %q", name, eng.Addr(name))
	}

	body = map[string]any{
		"proto":  "tcp",
		"listen": "127.0.0.1:0",
		"target": "100.64.45.20:1",
	}
	resp, text = apiRequest(t, eng.Addr("api"), "secret", http.MethodPost, "/v1/forwards", body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add forward status %d: %s", resp.StatusCode, text)
	}
	if err := json.Unmarshal([]byte(text), &created); err != nil {
		t.Fatalf("decode forward response: %v: %s", err, text)
	}
	name, _ = created["name"].(string)
	if name == "" || eng.Addr(name) == "" {
		t.Fatalf("forward was not registered: name=%q addr=%q body=%s", name, eng.Addr(name), text)
	}
	resp, text = apiRequest(t, eng.Addr("api"), "secret", http.MethodGet, "/v1/forwards", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("get forwards status %d: %s", resp.StatusCode, text)
	}
	if !strings.Contains(text, name) {
		t.Fatalf("forward list did not include %q: %s", name, text)
	}
	resp, text = apiRequest(t, eng.Addr("api"), "secret", http.MethodDelete, "/v1/forwards?name="+url.QueryEscape(name), nil)
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete forward status %d: %s", resp.StatusCode, text)
	}
}

func TestWireGuardSourceIPEnforced(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	echo := startEchoServer(t)
	defer echo.Close()

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	transparent := true
	serverCfg.Inbound.Transparent = &transparent
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.46.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.46.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.46.99/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{netip.PrefixFrom(hostIP, 32).String()},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)

	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()
	conn, err := clientEng.DialContext(ctx, "tcp", net.JoinHostPort(hostIP.String(), echo.Port))
	if err == nil {
		conn.Close()
		t.Fatal("dial succeeded even though server peer AllowedIPs did not permit the client's tunnel source IP")
	}
}

func TestTrafficShaperAppliesToTunnelTCP(t *testing.T) {
	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.58.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.58.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	tcpLn, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.58.1:18091"))
	if err != nil {
		t.Fatal(err)
	}
	defer tcpLn.Close()
	go serveEchoListener(tcpLn)

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.58.2/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.58.1/32"},
		PersistentKeepalive: 1,
	}}
	clientCfg.TrafficShaper = config.TrafficShaper{
		UploadBps:     4096,
		DownloadBps:   4096,
		LatencyMillis: 15,
	}
	clientEng := mustStart(t, clientCfg)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := clientEng.DialContext(ctx, "tcp", "100.64.58.1:18091")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	payload := bytes.Repeat([]byte("x"), 4096)
	reply := make([]byte, len(payload))
	start := time.Now()
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reply, payload) {
		t.Fatal("TCP echo payload mismatch")
	}
	if elapsed := time.Since(start); elapsed < 350*time.Millisecond {
		t.Fatalf("traffic shaper did not slow TCP enough: %v", elapsed)
	}
}

func TestRelayForwardingMultiPeer(t *testing.T) {
	serverKey, c1Key, c2Key := mustKey(t), mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	relay := true
	serverCfg.Relay.Enabled = &relay
	serverCfg.ACL.RelayDefault = acl.Allow
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.47.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{
		{PublicKey: c1Key.PublicKey().String(), AllowedIPs: []string{"100.64.47.2/32"}},
		{PublicKey: c2Key.PublicKey().String(), AllowedIPs: []string{"100.64.47.3/32"}},
	}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	clientCfg := func(key wgtypes.Key, addr, allowed string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = key.String()
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           serverKey.PublicKey().String(),
			Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
			AllowedIPs:          []string{allowed},
			PersistentKeepalive: 1,
		}}
		return cfg
	}
	c1 := mustStart(t, clientCfg(c1Key, "100.64.47.2/32", "100.64.47.3/32"))
	c2 := mustStart(t, clientCfg(c2Key, "100.64.47.3/32", "100.64.47.2/32"))

	ln, err := c2.ListenTCP(netip.MustParseAddrPort("100.64.47.3:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveEchoListener(ln)

	conn := retryEngineDial(t, c1, "tcp", "100.64.47.3:18080")
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	msg := []byte("relay-ok")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(msg, got) {
		t.Fatalf("relay echo mismatch: got %q", got)
	}
}

func TestRelayACLDenyThenAllow(t *testing.T) {
	serverKey, c1Key, c2Key := mustKey(t), mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	relay := true
	serverCfg.Relay.Enabled = &relay
	serverCfg.ACL.RelayDefault = acl.Deny
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.49.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{
		{PublicKey: c1Key.PublicKey().String(), AllowedIPs: []string{"100.64.49.2/32"}},
		{PublicKey: c2Key.PublicKey().String(), AllowedIPs: []string{"100.64.49.3/32"}},
	}
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	clientCfg := func(key wgtypes.Key, addr, allowed string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = key.String()
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           serverKey.PublicKey().String(),
			Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
			AllowedIPs:          []string{allowed},
			PersistentKeepalive: 1,
		}}
		return cfg
	}
	c1 := mustStart(t, clientCfg(c1Key, "100.64.49.2/32", "100.64.49.3/32"))
	c2 := mustStart(t, clientCfg(c2Key, "100.64.49.3/32", "100.64.49.2/32"))

	ln, err := c2.ListenTCP(netip.MustParseAddrPort("100.64.49.3:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveEchoListener(ln)

	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	conn, err := c1.DialContext(ctx, "tcp", "100.64.49.3:18080")
	cancel()
	if err == nil {
		_ = conn.Close()
		t.Fatal("relay connection succeeded while relay ACL default denied it")
	}

	if err := serverEng.SetACL(config.ACL{
		RelayDefault: acl.Deny,
		Relay: []acl.Rule{
			{
				Action:      acl.Allow,
				Source:      "100.64.49.2/32",
				Destination: "100.64.49.3/32",
				DestPort:    "18080",
			},
			{
				Action:      acl.Allow,
				Source:      "100.64.49.3/32",
				Destination: "100.64.49.2/32",
				SourcePort:  "18080",
			},
		},
	}); err != nil {
		t.Fatal(err)
	}

	conn = retryEngineDial(t, c1, "tcp", "100.64.49.3:18080")
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("relay-acl-ok")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("relay-acl-ok"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "relay-acl-ok" {
		t.Fatalf("relay ACL echo mismatch: got %q", got)
	}
}

func TestRelayConntrackACLWithThreePeers(t *testing.T) {
	serverKey, c1Key, c2Key, c3Key := mustKey(t), mustKey(t), mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	relay := true
	serverCfg.Relay.Enabled = &relay
	serverCfg.ACL.RelayDefault = acl.Deny
	serverCfg.ACL.Relay = []acl.Rule{{
		Action:      acl.Allow,
		Protocol:    "tcp",
		Source:      "100.64.50.2/32",
		Destination: "100.64.50.3/32",
		DestPort:    "18080",
	}}
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.50.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{
		{PublicKey: c1Key.PublicKey().String(), AllowedIPs: []string{"100.64.50.2/32"}},
		{PublicKey: c2Key.PublicKey().String(), AllowedIPs: []string{"100.64.50.3/32"}},
		{PublicKey: c3Key.PublicKey().String(), AllowedIPs: []string{"100.64.50.4/32"}},
	}
	mustStart(t, serverCfg)

	clientCfg := func(key wgtypes.Key, addr string, allowed ...string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = key.String()
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           serverKey.PublicKey().String(),
			Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
			AllowedIPs:          allowed,
			PersistentKeepalive: 1,
		}}
		return cfg
	}
	c1 := mustStart(t, clientCfg(c1Key, "100.64.50.2/32", "100.64.50.3/32"))
	c2 := mustStart(t, clientCfg(c2Key, "100.64.50.3/32", "100.64.50.2/32", "100.64.50.4/32"))
	c3 := mustStart(t, clientCfg(c3Key, "100.64.50.4/32", "100.64.50.3/32"))

	ln, err := c2.ListenTCP(netip.MustParseAddrPort("100.64.50.3:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveEchoListener(ln)

	conn := retryEngineDial(t, c1, "tcp", "100.64.50.3:18080")
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("relay-conntrack-three-peers")); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len("relay-conntrack-three-peers"))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if string(got) != "relay-conntrack-three-peers" {
		t.Fatalf("relay conntrack echo mismatch: got %q", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 700*time.Millisecond)
	denied, err := c3.DialContext(ctx, "tcp", "100.64.50.3:18080")
	cancel()
	if err == nil {
		_ = denied.Close()
		t.Fatal("third peer connected even though relay ACL only allows peer one")
	}
}

func TestStressImpairedNetworkAndAPIMutation(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	echo := startEchoServer(t)
	defer echo.Close()

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)
	impairedPort, closeProxy := startImpairedUDPProxy(t, serverPort)
	defer closeProxy()

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	transparent := true
	serverCfg.Inbound.Transparent = &transparent
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.48.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.48.2/32"},
	}}
	serverCfg.API.Listen = "127.0.0.1:0"
	serverCfg.API.Token = "secret"
	serverEng := mustStart(t, serverCfg)
	defer serverEng.Close()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.48.2/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", impairedPort),
		AllowedIPs:          []string{netip.PrefixFrom(hostIP, 32).String()},
		PersistentKeepalive: 1,
	}}
	clientCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	clientEng := mustStart(t, clientCfg)

	apiErr := make(chan error, 1)
	go func() {
		time.Sleep(200 * time.Millisecond)
		inboundRules := make([]map[string]any, 0, 81)
		for i := 0; i < 80; i++ {
			inboundRules = append(inboundRules, map[string]any{
				"action":      "deny",
				"source":      fmt.Sprintf("10.%d.0.0/16", i),
				"destination": "192.0.2.0/24",
			})
		}
		inboundRules = append(inboundRules, map[string]any{
			"action":           "allow",
			"source":           "100.64.48.2/32",
			"destination":      netip.PrefixFrom(hostIP, 32).String(),
			"destination_port": echo.Port,
		})
		relayRules := make([]map[string]any, 0, 65)
		for i := 0; i < 64; i++ {
			relayRules = append(relayRules, map[string]any{
				"action":      "deny",
				"source":      fmt.Sprintf("198.51.%d.0/24", i),
				"destination": "203.0.113.0/24",
			})
		}
		resp, body, err := apiRequestE(serverEng.Addr("api"), "secret", http.MethodPut, "/v1/acls", map[string]any{
			"inbound_default":  "deny",
			"outbound_default": "allow",
			"relay_default":    "deny",
			"inbound":          inboundRules,
			"relay":            relayRules,
		})
		if err != nil {
			apiErr <- err
			return
		}
		if resp.StatusCode != http.StatusNoContent {
			apiErr <- fmt.Errorf("API mutation status %d: %s", resp.StatusCode, body)
			return
		}
		apiErr <- nil
	}()

	dialer, err := proxy.SOCKS5("tcp", clientEng.Addr("socks5"), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	target := net.JoinHostPort(hostIP.String(), echo.Port)
	const streams = 4
	const bytesPerStream = 768 * 1024
	var wg sync.WaitGroup
	errc := make(chan error, streams)
	for i := 0; i < streams; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn := retryDial(t, dialer, target)
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
			payload := bytes.Repeat([]byte{byte('a' + i)}, bytesPerStream)
			writeErr := make(chan error, 1)
			go func() {
				_, err := conn.Write(payload)
				writeErr <- err
			}()
			got := make([]byte, len(payload))
			if _, err := io.ReadFull(conn, got); err != nil {
				errc <- err
				return
			}
			if err := <-writeErr; err != nil {
				errc <- err
				return
			}
			if !bytes.Equal(payload, got) {
				errc <- fmt.Errorf("stream %d payload mismatch", i)
			}
		}()
	}
	wg.Wait()
	close(errc)
	for err := range errc {
		if err != nil {
			t.Fatal(err)
		}
	}
	if err := <-apiErr; err != nil {
		t.Fatal(err)
	}
	gotACL := serverEng.ACL()
	if gotACL.InboundDefault != acl.Deny || len(gotACL.Inbound) != 81 || len(gotACL.Relay) != 64 {
		t.Fatalf("stress API ACL mutation did not install expected rule set: %+v", gotACL)
	}
	resp, body := apiRequest(t, serverEng.Addr("api"), "secret", http.MethodGet, "/v1/acls/relay", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relay ACL list status %d: %s", resp.StatusCode, body)
	}
	var relayRules []acl.Rule
	if err := json.Unmarshal([]byte(body), &relayRules); err != nil {
		t.Fatalf("decode relay ACL list: %v: %s", err, body)
	}
	if len(relayRules) != 64 {
		t.Fatalf("relay ACL list length mismatch: got %d", len(relayRules))
	}
}

func mustStart(t *testing.T, cfg config.Config) *engine.Engine {
	t.Helper()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(cfg, log.New(testLogWriter{t: t}, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(); err != nil {
		_ = eng.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = eng.Close() })
	return eng
}

type testLogWriter struct {
	t *testing.T
}

func (w testLogWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

func mustKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

type httpTestServer struct {
	*http.Server
	Port string
}

func startHTTPServer(t *testing.T) *httpTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("hello over wg"))
	})}
	go srv.Serve(ln)
	return &httpTestServer{Server: srv, Port: port}
}

func (s *httpTestServer) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_ = s.Shutdown(ctx)
}

type echoServer struct {
	ln   net.Listener
	Port string
}

func startEchoServer(t *testing.T) *echoServer {
	t.Helper()
	ln, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return &echoServer{ln: ln, Port: port}
}

func (s *echoServer) Close() { _ = s.ln.Close() }

func startProxyProtocolTCPEchoServer(t *testing.T) (net.Listener, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	headers := make(chan string, 4)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil {
					return
				}
				headers <- strings.TrimSuffix(line, "\r\n")
				_, _ = io.Copy(c, br)
			}()
		}
	}()
	return ln, headers
}

func startProxyProtocolUDPEchoServer(t *testing.T) (net.PacketConn, <-chan string) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	headers := make(chan string, 16)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			packet := buf[:n]
			if payload, header, ok := testStripProxyProtocolV2UDP(packet); ok {
				headers <- header
				_, _ = pc.WriteTo(payload, addr)
				continue
			}
			idx := bytes.Index(packet, []byte("\r\n"))
			if idx < 0 {
				continue
			}
			headers <- string(packet[:idx])
			_, _ = pc.WriteTo(packet[idx+2:], addr)
		}
	}()
	return pc, headers
}

type httpConnectProxy struct {
	ln      net.Listener
	targets chan string
	count   atomic.Int64
}

func startHTTPConnectProxy(t *testing.T) (*httpConnectProxy, <-chan string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := &httpConnectProxy{
		ln:      ln,
		targets: make(chan string, 32),
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p, p.targets
}

func (p *httpConnectProxy) Addr() net.Addr {
	return p.ln.Addr()
}

func (p *httpConnectProxy) Close() error {
	return p.ln.Close()
}

func (p *httpConnectProxy) Count() int64 {
	return p.count.Load()
}

func (p *httpConnectProxy) serve(c net.Conn) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect || req.Host == "" {
		_, _ = io.WriteString(c, "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
		return
	}
	p.count.Add(1)
	select {
	case p.targets <- req.Host:
	default:
	}
	target, err := net.DialTimeout("tcp", req.Host, 5*time.Second)
	if err != nil {
		_, _ = io.WriteString(c, "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
		return
	}
	defer target.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	_ = c.SetDeadline(time.Time{})
	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(target, br)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(c, target)
		errc <- err
	}()
	<-errc
}

func testStripProxyProtocolV2UDP(packet []byte) ([]byte, string, bool) {
	signature := []byte{'\r', '\n', '\r', '\n', 0x00, '\r', '\n', 'Q', 'U', 'I', 'T', '\n'}
	if len(packet) < 16 || !bytes.Equal(packet[:12], signature) {
		return nil, "", false
	}
	ln := int(binary.BigEndian.Uint16(packet[14:16]))
	if len(packet) < 16+ln {
		return nil, "", false
	}
	payload := packet[16+ln:]
	if packet[12] != 0x21 || packet[13] != 0x12 || ln < 12 {
		return payload, "unsupported-v2", true
	}
	var src4, dst4 [4]byte
	copy(src4[:], packet[16:20])
	copy(dst4[:], packet[20:24])
	src := netip.AddrPortFrom(netip.AddrFrom4(src4), binary.BigEndian.Uint16(packet[24:26]))
	dst := netip.AddrPortFrom(netip.AddrFrom4(dst4), binary.BigEndian.Uint16(packet[26:28]))
	return payload, src.String() + ">" + dst.String(), true
}

func socksHTTPGet(t *testing.T, socksAddr, target string) string {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn := retryDial(t, dialer, target)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	resp, err := http.ReadResponse(bufioNewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func socksEcho(t *testing.T, socksAddr, target string, msg []byte) []byte {
	t.Helper()
	dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}
	conn := retryDial(t, dialer, target)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	return got
}

func httpProxyGet(t *testing.T, proxyAddr, target string) string {
	t.Helper()
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(&url.URL{Scheme: "http", Host: proxyAddr}),
		},
	}
	resp, err := client.Get("http://" + target + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func httpProxyAbsoluteFormGet(t *testing.T, proxyAddr, targetURL string) (int, string) {
	t.Helper()
	u, err := url.Parse(targetURL)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	if _, err := fmt.Fprintf(c, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetURL, u.Host); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(body)
}

func httpProxyGetUnix(t *testing.T, proxySocket, target string) string {
	t.Helper()
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: func(*http.Request) (*url.URL, error) {
				return &url.URL{Scheme: "http", Host: "uwg"}, nil
			},
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", proxySocket)
			},
		},
	}
	resp, err := client.Get("http://" + target + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func httpProxyConnectGet(t *testing.T, proxyAddr, target string) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(c)
	if _, err := fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("HTTP CONNECT status=%d", resp.StatusCode)
	}
	if _, err := fmt.Fprintf(c, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target); err != nil {
		t.Fatal(err)
	}
	resp, err = http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func directHTTPGet(t *testing.T, target string) string {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get("http://" + target + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(body)
}

func retryDial(t *testing.T, dialer proxy.Dialer, target string) net.Conn {
	t.Helper()
	var last error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		c, err := dialer.Dial("tcp", target)
		if err == nil {
			return c
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("dial %s: %v", target, last)
	return nil
}

func retryEngineDial(t *testing.T, eng *engine.Engine, network, target string) net.Conn {
	t.Helper()
	var last error
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		c, err := eng.DialContext(ctx, network, target)
		cancel()
		if err == nil {
			return c
		}
		last = err
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("engine dial %s: %v", target, last)
	return nil
}

func addrPortFromNetAddrTest(addr net.Addr) netip.AddrPort {
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port))
	case *net.UDPAddr:
		ip, _ := netip.AddrFromSlice(a.IP)
		return netip.AddrPortFrom(ip.Unmap(), uint16(a.Port))
	}
	ap, _ := netip.ParseAddrPort(addr.String())
	return ap
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func sendMalformedWireGuard(t *testing.T, port int) {
	t.Helper()
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	for _, packet := range [][]byte{
		{},
		{0xff},
		bytes.Repeat([]byte{0x42}, 16),
		bytes.Repeat([]byte{0x13}, 128),
	} {
		_, _ = c.Write(packet)
	}
}

func nonLoopbackIPv4(t *testing.T) netip.Addr {
	t.Helper()
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatal(err)
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			p, err := netip.ParsePrefix(a.String())
			if err == nil && p.Addr().Is4() {
				return p.Addr()
			}
		}
	}
	t.Skip("no non-loopback IPv4 address available for transparent host-dial test")
	return netip.Addr{}
}

func hostPingSupported(dst netip.Addr) bool {
	pc, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		return false
	}
	defer pc.Close()
	payload := []byte("uwgsocks-host-ping-check")
	packet, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 0x4321, Seq: 1, Data: payload},
	}).Marshal(nil)
	if err != nil {
		return false
	}
	_ = pc.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := pc.WriteTo(packet, &net.IPAddr{IP: net.IP(dst.AsSlice())}); err != nil {
		return false
	}
	buf := make([]byte, 1500)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			return false
		}
		msg, err := icmp.ParseMessage(1, buf[:n])
		if err != nil {
			continue
		}
		echo, ok := msg.Body.(*icmp.Echo)
		if ok && msg.Type == ipv4.ICMPTypeEchoReply && bytes.Equal(echo.Data, payload) {
			return true
		}
	}
}

func serveEchoListener(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}()
	}
}

func serveUDPEcho(pc net.PacketConn) {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(buf[:n], addr)
	}
}

func udpRoundTrip(t *testing.T, conn net.Conn, msg []byte) []byte {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, max(1, len(msg)))
	n, err := conn.Read(got)
	if err != nil {
		t.Fatal(err)
	}
	got = got[:n]
	if !bytes.Equal(got, msg) {
		t.Fatalf("UDP echo mismatch: got %q want %q", got, msg)
	}
	return got
}

func echoOverEngine(t *testing.T, eng *engine.Engine, target string, msg []byte) {
	t.Helper()
	conn := retryEngineDial(t, eng, "tcp", target)
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("engine echo mismatch: got %q want %q", got, msg)
	}
}

type socksUDPClient struct {
	*net.UDPConn
	control net.Conn
}

func (c *socksUDPClient) Close() error {
	_ = c.control.Close()
	return c.UDPConn.Close()
}

func socksControl(t *testing.T, socksAddr string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	var resp [2]byte
	if _, err := io.ReadFull(conn, resp[:]); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if resp != [2]byte{0x05, 0x00} {
		_ = conn.Close()
		t.Fatalf("unexpected SOCKS greeting response: %v", resp)
	}
	return conn
}

func socksControlAuth(t *testing.T, socksAddr, username, password string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", socksAddr, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x02}); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	var method [2]byte
	if _, err := io.ReadFull(conn, method[:]); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if method != [2]byte{0x05, 0x02} {
		_ = conn.Close()
		t.Fatalf("unexpected SOCKS auth method response: %v", method)
	}
	auth := []byte{0x01, byte(len(username))}
	auth = append(auth, username...)
	auth = append(auth, byte(len(password)))
	auth = append(auth, password...)
	if _, err := conn.Write(auth); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	var status [2]byte
	if _, err := io.ReadFull(conn, status[:]); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if status != [2]byte{0x01, 0x00} {
		_ = conn.Close()
		t.Fatalf("SOCKS username/password auth failed: %v", status)
	}
	return conn
}

func socksUDPAssociate(t *testing.T, socksAddr string) net.Conn {
	t.Helper()
	udp, _ := socksUDPAssociateRelay(t, socksAddr)
	return udp
}

func socksUDPAssociateRelay(t *testing.T, socksAddr string) (net.Conn, netip.AddrPort) {
	t.Helper()
	control := socksControl(t, socksAddr)
	if _, err := control.Write(socksRequestBytes(0x03, netip.MustParseAddrPort("0.0.0.0:0"))); err != nil {
		_ = control.Close()
		t.Fatal(err)
	}
	rep, relay := readSOCKSReply(t, control)
	if rep != 0 {
		_ = control.Close()
		t.Fatalf("UDP ASSOCIATE failed with reply %d", rep)
	}
	ua := net.UDPAddrFromAddrPort(relay)
	udp, err := net.DialUDP("udp", nil, ua)
	if err != nil {
		_ = control.Close()
		t.Fatal(err)
	}
	return &socksUDPClient{UDPConn: udp, control: control}, relay
}

func socksBind(t *testing.T, socksAddr string, requested netip.AddrPort) (netip.AddrPort, <-chan error) {
	t.Helper()
	control := socksControl(t, socksAddr)
	if _, err := control.Write(socksRequestBytes(0x02, requested)); err != nil {
		_ = control.Close()
		t.Fatal(err)
	}
	rep, bound := readSOCKSReply(t, control)
	if rep != 0 {
		_ = control.Close()
		t.Fatalf("SOCKS BIND failed with reply %d", rep)
	}
	done := make(chan error, 1)
	go func() {
		defer control.Close()
		rep, _, err := readSOCKSReplyE(control)
		if err != nil {
			done <- err
			return
		}
		if rep != 0 {
			done <- fmt.Errorf("SOCKS BIND second reply %d", rep)
			return
		}
		_ = control.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, len("bind-ok"))
		if _, err := io.ReadFull(control, buf); err != nil {
			done <- err
			return
		}
		_, err = control.Write(buf)
		done <- err
	}()
	return bound, done
}

func socksConnectReply(t *testing.T, socksAddr string, dst netip.AddrPort) byte {
	t.Helper()
	control := socksControl(t, socksAddr)
	defer control.Close()
	if _, err := control.Write(socksRequestBytes(0x01, dst)); err != nil {
		t.Fatal(err)
	}
	rep, _ := readSOCKSReply(t, control)
	return rep
}

func socksConnectReplyAuth(t *testing.T, socksAddr, username, password string, dst netip.AddrPort) byte {
	t.Helper()
	control := socksControlAuth(t, socksAddr, username, password)
	defer control.Close()
	if _, err := control.Write(socksRequestBytes(0x01, dst)); err != nil {
		t.Fatal(err)
	}
	rep, _ := readSOCKSReply(t, control)
	return rep
}

func socksRequestBytes(cmd byte, dst netip.AddrPort) []byte {
	out := []byte{0x05, cmd, 0x00}
	out = append(out, socksAddrBytes(dst)...)
	return out
}

func socksAddrBytes(dst netip.AddrPort) []byte {
	var out []byte
	if dst.Addr().Is6() {
		out = append(out, 0x04)
		ip := dst.Addr().As16()
		out = append(out, ip[:]...)
	} else {
		out = append(out, 0x01)
		ip := dst.Addr().As4()
		out = append(out, ip[:]...)
	}
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], dst.Port())
	out = append(out, p[:]...)
	return out
}

func readSOCKSReply(t *testing.T, r io.Reader) (byte, netip.AddrPort) {
	t.Helper()
	rep, addr, err := readSOCKSReplyE(r)
	if err != nil {
		t.Fatal(err)
	}
	return rep, addr
}

func readSOCKSReplyE(r io.Reader) (byte, netip.AddrPort, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	if hdr[0] != 0x05 {
		return 0, netip.AddrPort{}, fmt.Errorf("invalid SOCKS reply version %d", hdr[0])
	}
	var addr netip.Addr
	switch hdr[3] {
	case 0x01:
		var b [4]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, netip.AddrPort{}, err
		}
		addr = netip.AddrFrom4(b)
	case 0x04:
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return 0, netip.AddrPort{}, err
		}
		addr = netip.AddrFrom16(b)
	default:
		return 0, netip.AddrPort{}, fmt.Errorf("unsupported SOCKS reply address type %d", hdr[3])
	}
	var p [2]byte
	if _, err := io.ReadFull(r, p[:]); err != nil {
		return 0, netip.AddrPort{}, err
	}
	return hdr[1], netip.AddrPortFrom(addr, binary.BigEndian.Uint16(p[:])), nil
}

func socksUDPDatagram(t *testing.T, dst netip.AddrPort, payload []byte) []byte {
	t.Helper()
	out := []byte{0x00, 0x00, 0x00}
	out = append(out, socksAddrBytes(dst)...)
	out = append(out, payload...)
	return out
}

func readSOCKSUDPDatagram(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 64*1024)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if n < 10 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 {
		t.Fatalf("invalid SOCKS UDP datagram: %x", buf[:n])
	}
	off := 4
	switch buf[3] {
	case 0x01:
		off += 4
	case 0x04:
		off += 16
	default:
		t.Fatalf("invalid SOCKS UDP address type: %d", buf[3])
	}
	off += 2
	if off > n {
		t.Fatalf("truncated SOCKS UDP datagram: %x", buf[:n])
	}
	return append([]byte(nil), buf[off:n]...)
}

func freeUDP6Port(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback UDP is unavailable: %v", err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func serveStaticTunnelDNS(pc net.PacketConn, records map[string]netip.Addr) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		var req dns.Msg
		if err := req.Unpack(buf[:n]); err != nil {
			continue
		}
		resp := new(dns.Msg)
		resp.SetReply(&req)
		for _, q := range req.Question {
			ip, ok := records[strings.ToLower(q.Name)]
			if !ok || q.Qclass != dns.ClassINET {
				continue
			}
			switch {
			case q.Qtype == dns.TypeA && ip.Is4():
				resp.Answer = append(resp.Answer, &dns.A{
					Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 30},
					A:   net.IP(ip.AsSlice()),
				})
			case q.Qtype == dns.TypeAAAA && ip.Is6():
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 30},
					AAAA: net.IP(ip.AsSlice()),
				})
			}
		}
		packed, err := resp.Pack()
		if err == nil {
			_, _ = pc.WriteTo(packed, addr)
		}
	}
}

func apiRequest(t *testing.T, addr, token, method, path string, body any) (*http.Response, string) {
	t.Helper()
	resp, text, err := apiRequestE(addr, token, method, path, body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, text
}

func apiRequestE(addr, token, method, path string, body any) (*http.Response, string, error) {
	var r io.Reader
	if body != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return nil, "", err
		}
		r = &buf
	}
	req, err := http.NewRequest(method, "http://"+addr+path, r)
	if err != nil {
		return nil, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", err
	}
	return resp, string(b), nil
}

func apiRawRequest(t *testing.T, addr, token, method, path, contentType string, body []byte) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, "http://"+addr+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(b)
}

func waitPeerStatus(t *testing.T, eng *engine.Engine, publicKey string) engine.PeerStatus {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		status, err := eng.Status()
		if err != nil {
			t.Fatal(err)
		}
		for _, peer := range status.Peers {
			if peer.PublicKey == publicKey && peer.HasHandshake && (peer.TransmitBytes > 0 || peer.ReceiveBytes > 0) {
				return peer
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("peer %s never reported handshake and transfer counters in status: %+v", publicKey, status)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func startLossyUDPProxy(t *testing.T, serverPort int, loss float64) (int, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(serverPort)))
	rng := mrand.New(mrand.NewSource(1))
	var client net.Addr
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if rng.Float64() < loss {
				continue
			}
			dst := net.Addr(server)
			if addr.String() == server.String() {
				if client == nil {
					continue
				}
				dst = client
			} else {
				client = addr
			}
			_, _ = pc.WriteTo(buf[:n], dst)
		}
	}()
	closeFn := func() {
		_ = pc.Close()
		<-done
	}
	return pc.LocalAddr().(*net.UDPAddr).Port, closeFn
}

func startImpairedUDPProxy(t *testing.T, serverPort int) (int, func()) {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := net.UDPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(serverPort)))
	rng := mrand.New(mrand.NewSource(2))
	type datagram struct {
		buf   []byte
		dst   net.Addr
		delay time.Duration
	}
	queue := make(chan datagram, 256)
	var client net.Addr
	start := time.Now()
	done := make(chan struct{})
	for i := 0; i < 8; i++ {
		go func() {
			for d := range queue {
				timer := time.NewTimer(d.delay)
				<-timer.C
				_, _ = pc.WriteTo(d.buf, d.dst)
			}
		}()
	}
	go func() {
		defer close(done)
		buf := make([]byte, 64*1024)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				close(queue)
				return
			}
			dst := net.Addr(server)
			if addr.String() == server.String() {
				if client == nil {
					continue
				}
				dst = client
			} else {
				client = addr
			}
			elapsed := time.Since(start).Seconds()
			loss := 0.001 + 0.004*(0.5+0.5*math.Sin(elapsed*5))
			if rng.Float64() < loss {
				continue
			}
			delay := time.Duration(rng.Intn(4)) * time.Millisecond
			packet := append([]byte(nil), buf[:n]...)
			select {
			case queue <- datagram{buf: packet, dst: dst, delay: delay}:
			default:
				// Tail drop when the simulated router queue is full.
			}
		}
	}()
	closeFn := func() {
		_ = pc.Close()
		<-done
	}
	return pc.LocalAddr().(*net.UDPAddr).Port, closeFn
}

type readWrapper interface {
	Read([]byte) (int, error)
}

func bufioNewReader(r readWrapper) *bufio.Reader {
	return bufio.NewReader(r)
}
