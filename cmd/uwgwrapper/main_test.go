//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package main

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
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestFDProxySpawnArgsKeepTokenReachable(t *testing.T) {
	args := fdproxySpawnArgs("/tmp/fd.sock", "http://127.0.0.1:9090", "/uwg/socket", true, false, "demo-token", true)
	want := []string{
		"--mode=fdproxy",
		"--listen", "/tmp/fd.sock",
		"--api", "http://127.0.0.1:9090",
		"--socket-path", "/uwg/socket",
		"--allow-bind=true",
		"--allow-lowbind=false",
		"-v",
		"--token", "demo-token",
	}
	if len(args) != len(want) {
		t.Fatalf("len(args) = %d, want %d: %v", len(args), len(want), args)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q; args=%v", i, args[i], want[i], args)
		}
	}
}

func TestStdioConnectTargetSelection(t *testing.T) {
	target, err := stdioConnectTarget("100.64.1.2:22", nil)
	if err != nil {
		t.Fatal(err)
	}
	if target != "100.64.1.2:22" {
		t.Fatalf("flag target = %q", target)
	}
	target, err = stdioConnectTarget("", []string{"100.64.1.3:22"})
	if err != nil {
		t.Fatal(err)
	}
	if target != "100.64.1.3:22" {
		t.Fatalf("arg target = %q", target)
	}
	if _, err := stdioConnectTarget("100.64.1.2:22", []string{"100.64.1.3:22"}); err == nil {
		t.Fatal("expected conflict error when both flag and positional target are set")
	}
}

func TestParseStdioConnectTarget(t *testing.T) {
	got, err := parseStdioConnectTarget("100.64.1.2:22")
	if err != nil {
		t.Fatal(err)
	}
	if got != netip.MustParseAddrPort("100.64.1.2:22") {
		t.Fatalf("target = %s", got)
	}
	if _, err := parseStdioConnectTarget("ssh.internal:22"); err == nil {
		t.Fatal("expected hostname target to be rejected")
	}
}

func TestRunStdioConnectEcho(t *testing.T) {
	serverKey, clientKey := mustWrapperKey(t), mustWrapperKey(t)
	serverPort := freeWrapperUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.95.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.95.2/32"},
	}}
	serverEng := mustStartWrapperEngine(t, serverCfg)
	defer serverEng.Close()

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.95.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, len("stdio via uwgwrapper"))
		if _, err := io.ReadFull(conn, buf); err == nil {
			_, _ = conn.Write(buf)
		}
	}()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.95.2/32"}
	clientCfg.API.Listen = "127.0.0.1:0"
	clientCfg.API.Token = "secret"
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.64.95.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStartWrapperEngine(t, clientCfg)
	defer clientEng.Close()

	stdin := bytes.NewBufferString("stdio via uwgwrapper")
	var stdout bytes.Buffer
	if err := runStdioConnect("http://"+clientEng.Addr("api"), "secret", "/uwg/socket", "100.64.95.1:18080", stdin, &stdout); err != nil {
		t.Fatal(err)
	}
	if stdout.String() != "stdio via uwgwrapper" {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func mustWrapperKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func freeWrapperUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func mustStartWrapperEngine(t *testing.T, cfg config.Config) *engine.Engine {
	t.Helper()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(); err != nil {
		_ = eng.Close()
		t.Fatal(err)
	}
	return eng
}
