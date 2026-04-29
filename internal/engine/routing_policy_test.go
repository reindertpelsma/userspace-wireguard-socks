// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine_test

// Tests for the routing decision order documented in docs/features/proxies-and-forwards.md.
//
// Routing order for SOCKS5/HTTP outbound connections:
//   1. Local tunnel address / localhost → reverse forward or host_forward.proxy
//   2. Tunnel address with no reverse forward → host_forward.proxy (or reject)
//   3. Reverse-forward userspace listener → dial reverse-forward target
//   4. Peer AllowedIPs (most-specific-prefix first) → WireGuard netstack
//   5. Address= subnet reservation → reject (no leak to direct)
//   6. Outbound proxy fallback (most-specific subnet wins; HTTP proxy is TCP-only)
//   7. fallback_direct: false → reject
//   8. fallback_direct: true → direct host dial

import (
	"bytes"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

// TestRoutingReverseFwdBeatsAllowedIPs verifies step 3 < step 4: when the same
// IP:port is covered by both a reverse-forward listener AND a peer AllowedIPs
// entry, the reverse forward wins and the target is dialled directly instead of
// being routed into the WireGuard netstack.
func TestRoutingReverseFwdBeatsAllowedIPs(t *testing.T) {
	echo := startEchoServer(t)
	defer echo.Close()

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	// Server peer: WG address 100.64.62.2/32 with no TCP listener at :18080.
	// If traffic were incorrectly routed via AllowedIPs the connection would fail.
	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.62.2/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.62.1/32"},
	}}
	mustStart(t, serverCfg)

	reverseTarget := netip.MustParseAddrPort("100.64.62.2:18080")

	proxyCfg := config.Default()
	proxyCfg.WireGuard.PrivateKey = clientKey.String()
	proxyCfg.WireGuard.Addresses = []string{"100.64.62.1/32"}
	proxyCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	proxyCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort)),
		AllowedIPs:          []string{"100.64.62.2/32"},
		PersistentKeepalive: 1,
	}}
	// Reverse forward at the same address/port that AllowedIPs also covers.
	proxyCfg.ReverseForwards = []config.Forward{{
		Proto:  "tcp",
		Listen: reverseTarget.String(),
		Target: net.JoinHostPort("127.0.0.1", echo.Port),
	}}
	proxyEng := mustStart(t, proxyCfg)

	got := socksEcho(t, proxyEng.Addr("socks5"), reverseTarget.String(), []byte("reverse-beats-allowedips"))
	if !bytes.Equal(got, []byte("reverse-beats-allowedips")) {
		t.Fatalf("reverse forward did not take priority over AllowedIPs routing: got %q", got)
	}
}

// TestRoutingAllowedIPsMostSpecificPrefixFirst verifies step 4: when two peers
// have overlapping AllowedIPs prefixes, the more specific prefix wins.
func TestRoutingAllowedIPsMostSpecificPrefixFirst(t *testing.T) {
	broadKey, specificKey, clientKey := mustKey(t), mustKey(t), mustKey(t)
	broadPort := freeUDPPort(t)
	specificPort := freeUDPPort(t)

	const targetAddr = "100.64.63.200"

	// Broad server: AllowedIPs /25 covers 100.64.63.0-127. Has NO listener at targetAddr.
	broadCfg := config.Default()
	broadCfg.WireGuard.PrivateKey = broadKey.String()
	broadCfg.WireGuard.ListenPort = &broadPort
	broadCfg.WireGuard.Addresses = []string{"100.64.63.5/32"}
	broadCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.63.1/32"},
	}}
	mustStart(t, broadCfg)

	// Specific server: AllowedIPs /32 = exactly targetAddr. Has a TCP echo there.
	specificCfg := config.Default()
	specificCfg.WireGuard.PrivateKey = specificKey.String()
	specificCfg.WireGuard.ListenPort = &specificPort
	specificCfg.WireGuard.Addresses = []string{targetAddr + "/32"}
	specificCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.63.1/32"},
	}}
	specificEng := mustStart(t, specificCfg)
	ln, err := specificEng.ListenTCP(netip.MustParseAddrPort(targetAddr + ":18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveEchoListener(ln)

	proxyCfg := config.Default()
	proxyCfg.WireGuard.PrivateKey = clientKey.String()
	proxyCfg.WireGuard.Addresses = []string{"100.64.63.1/32"}
	proxyCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	proxyCfg.WireGuard.Peers = []config.Peer{
		{
			// /25 broad peer — covers 100.64.63.0-127 but not 100.64.63.200
			PublicKey:           broadKey.PublicKey().String(),
			Endpoint:            net.JoinHostPort("127.0.0.1", strconv.Itoa(broadPort)),
			AllowedIPs:          []string{"100.64.63.0/25"},
			PersistentKeepalive: 1,
		},
		{
			// /32 specific peer — exact match for targetAddr
			PublicKey:           specificKey.PublicKey().String(),
			Endpoint:            net.JoinHostPort("127.0.0.1", strconv.Itoa(specificPort)),
			AllowedIPs:          []string{targetAddr + "/32"},
			PersistentKeepalive: 1,
		},
	}
	proxyEng := mustStart(t, proxyCfg)

	got := socksEcho(t, proxyEng.Addr("socks5"), targetAddr+":18080", []byte("most-specific-prefix"))
	if !bytes.Equal(got, []byte("most-specific-prefix")) {
		t.Fatalf("most-specific AllowedIPs peer was not used: got %q", got)
	}
}

// TestRoutingAddressSubnetBlocksLeak verifies step 5: a destination inside an
// Address= subnet reservation but not covered by any peer AllowedIPs is rejected
// rather than leaking to the direct fallback path.
func TestRoutingAddressSubnetBlocksLeak(t *testing.T) {
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	// Address 10.20.20.2/24 means 10.20.20.0/24 is a "virtual" subnet reservation.
	cfg.WireGuard.Addresses = []string{"100.64.64.1/32", "10.20.20.2/24"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	fallback := true // even with fallback_direct=true, Address= subnet must be blocked
	cfg.Proxy.FallbackDirect = &fallback
	eng := mustStart(t, cfg)

	// Target is inside the Address= /24 reservation but no peer claims it via AllowedIPs.
	rep := socksConnectReply(t, eng.Addr("socks5"), netip.MustParseAddrPort("10.20.20.50:80"))
	if rep == 0 {
		t.Fatal("address-subnet destination leaked to direct fallback instead of being rejected")
	}
}

// TestRoutingFallbackDirectFalseRejectsNonPeer verifies step 7: when
// fallback_direct=false and no outbound proxy covers the destination, a
// non-peer IP is rejected rather than being dialled directly.
func TestRoutingFallbackDirectFalseRejectsNonPeer(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	echo := startEchoServer(t)
	defer echo.Close()

	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.65.1/32"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	fallback := false
	cfg.Proxy.FallbackDirect = &fallback
	eng := mustStart(t, cfg)

	target := netip.MustParseAddrPort(net.JoinHostPort(hostIP.String(), echo.Port))
	rep := socksConnectReply(t, eng.Addr("socks5"), target)
	if rep == 0 {
		t.Fatal("non-peer connection succeeded with fallback_direct=false; should have been rejected")
	}
}

// TestRoutingOutboundProxyMostSpecificSubnetWins verifies step 6: when two
// outbound proxy rules both cover the destination, the rule with the more
// specific subnet prefix wins.
func TestRoutingOutboundProxyMostSpecificSubnetWins(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)
	echo := startEchoServer(t)
	defer echo.Close()

	broadProxy, broadTargets := startHTTPConnectProxy(t)
	specificProxy, specificTargets := startHTTPConnectProxy(t)
	defer broadProxy.Close()
	defer specificProxy.Close()

	honorEnv := false
	fallback := false
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.66.1/32"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	cfg.Proxy.HonorEnvironment = &honorEnv
	cfg.Proxy.FallbackDirect = &fallback
	cfg.Proxy.OutboundProxies = []config.OutboundProxy{
		{
			Type:    "http",
			Address: broadProxy.Addr().String(),
			Roles:   []string{"socks"},
			Subnets: []string{"0.0.0.0/0"}, // broad: matches everything
		},
		{
			Type:    "http",
			Address: specificProxy.Addr().String(),
			Roles:   []string{"socks"},
			Subnets: []string{netip.PrefixFrom(hostIP, 32).String()}, // specific /32
		},
	}
	eng := mustStart(t, cfg)

	target := net.JoinHostPort(hostIP.String(), echo.Port)
	got := socksEcho(t, eng.Addr("socks5"), target, []byte("specific-proxy-wins"))
	if !bytes.Equal(got, []byte("specific-proxy-wins")) {
		t.Fatalf("most-specific-subnet proxy echo mismatch: got %q", got)
	}

	// Specific proxy must have been used.
	select {
	case gotTarget := <-specificTargets:
		if gotTarget != target {
			t.Fatalf("specific proxy saw target %q, want %q", gotTarget, target)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("specific-subnet outbound proxy was not used")
	}
	// Broad proxy must NOT have been used.
	select {
	case bad := <-broadTargets:
		t.Fatalf("broad /0 proxy was incorrectly preferred over the specific /32 rule (saw %q)", bad)
	default:
	}
}

// TestRoutingHTTPProxyNotUsedForUDP verifies step 6 footnote: HTTP CONNECT
// proxies handle only TCP; UDP connections fall through to the next matching
// SOCKS5 proxy or fail if none exists and fallback_direct is false.
func TestRoutingHTTPProxyNotUsedForUDP(t *testing.T) {
	hostIP := nonLoopbackIPv4(t)

	hostUDP, err := net.ListenPacket("udp", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hostUDP.Close()
	go serveUDPEcho(hostUDP)
	udpPort := hostUDP.LocalAddr().(*net.UDPAddr).Port

	httpProxy, httpTargets := startHTTPConnectProxy(t)
	defer httpProxy.Close()

	honorEnv := false
	fallback := false
	key := mustKey(t)
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = key.String()
	cfg.WireGuard.Addresses = []string{"100.64.67.1/32"}
	cfg.Proxy.SOCKS5 = "127.0.0.1:0"
	cfg.Proxy.HonorEnvironment = &honorEnv
	cfg.Proxy.FallbackDirect = &fallback
	// Only an HTTP outbound proxy — cannot relay UDP.
	cfg.Proxy.OutboundProxies = []config.OutboundProxy{{
		Type:    "http",
		Address: httpProxy.Addr().String(),
		Roles:   []string{"socks"},
		Subnets: []string{netip.PrefixFrom(hostIP, 32).String()},
	}}
	eng := mustStart(t, cfg)

	udpTarget := netip.MustParseAddrPort(net.JoinHostPort(hostIP.String(), strconv.Itoa(udpPort)))

	// UDP ASSOCIATE to the host IP via SOCKS5 should fail: the only outbound
	// proxy is HTTP which cannot relay UDP, and fallback_direct is false.
	udpConn := socksUDPAssociate(t, eng.Addr("socks5"))
	defer udpConn.Close()
	_ = udpConn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := udpConn.Write(socksUDPDatagram(t, udpTarget, []byte("http-proxy-udp-attempt"))); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 512)
	_, readErr := udpConn.Read(buf)
	if readErr == nil {
		t.Fatal("UDP datagram succeeded through HTTP-only proxy; expected no response")
	}

	// HTTP proxy must not have been contacted for the UDP attempt.
	select {
	case bad := <-httpTargets:
		t.Fatalf("HTTP proxy was incorrectly used for UDP: saw CONNECT target %q", bad)
	default:
	}
}
