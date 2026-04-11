// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine_test

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"testing"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
	"golang.org/x/net/proxy"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func BenchmarkLoopbackSOCKSThroughput(b *testing.B) {
	serverKey, clientKey := mustBenchKey(b), mustBenchKey(b)
	serverPort := freeBenchUDPPort(b)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.60.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.60.2/32"},
	}}
	serverEng := mustStartBenchEngine(b, serverCfg)

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.60.1:18080"))
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = ln.Close() })
	go serveEchoListener(ln)

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.60.2/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.60.1/32"},
		PersistentKeepalive: 1,
	}}
	clientCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	clientEng := mustStartBenchEngine(b, clientCfg)

	dialer, err := proxy.SOCKS5("tcp", clientEng.Addr("socks5"), nil, proxy.Direct)
	if err != nil {
		b.Fatal(err)
	}
	conn, err := dialer.Dial("tcp", "100.64.60.1:18080")
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()

	payload := bytes.Repeat([]byte("x"), 1024*1024)
	got := make([]byte, len(payload))
	b.SetBytes(int64(len(payload)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(payload); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, got); err != nil {
			b.Fatal(err)
		}
	}
}

func mustStartBenchEngine(b *testing.B, cfg config.Config) *engine.Engine {
	b.Helper()
	if err := cfg.Normalize(); err != nil {
		b.Fatal(err)
	}
	eng, err := engine.New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		b.Fatal(err)
	}
	if err := eng.Start(); err != nil {
		_ = eng.Close()
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = eng.Close() })
	return eng
}

func mustBenchKey(b *testing.B) wgtypes.Key {
	b.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		b.Fatal(err)
	}
	return key
}

func freeBenchUDPPort(b *testing.B) int {
	b.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}
