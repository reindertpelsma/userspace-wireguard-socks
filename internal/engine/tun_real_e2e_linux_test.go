//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

// TestRealLinuxTUNEngineE2E creates a real kernel TUN device, wires it into an
// engine instance, establishes a WireGuard session with a second engine, and
// sends real IP traffic through the TUN interface to verify full-stack routing.
//
// Gate: UWG_TEST_REAL_TUN=1. Requires root/CAP_NET_ADMIN (e.g., inside a
// --privileged Docker container or a bare-metal CI runner with NET_ADMIN).

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
	hosttun "github.com/reindertpelsma/userspace-wireguard-socks/internal/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func genKeyForRealTUNTest(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func freeUDPPortForRealTUNTest(t *testing.T) int {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

func TestRealLinuxTUNEngineE2E(t *testing.T) {
	if !testconfig.Get().RealTUN {
		t.Skip("set UWG_TEST_REAL_TUN=1 or -uwgs-real-tun to run real host TUN end-to-end traffic test")
	}
	if err := hosttun.RequireRootForRealTUN(); err != nil {
		t.Skip(err.Error())
	}

	// WireGuard addresses
	const (
		serverWGAddr = "198.19.1.1/32"
		clientWGAddr = "198.19.1.2/32"
		serverHost   = "198.19.1.1"
		clientHost   = "198.19.1.2"
		echoPort     = 18088
	)

	serverKey, clientKey := genKeyForRealTUNTest(t), genKeyForRealTUNTest(t)
	serverPort := freeUDPPortForRealTUNTest(t)

	// Server engine: WG only, TCP echo listener on its WG address.
	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{serverWGAddr}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{clientWGAddr},
	}}
	serverEng, err := New(serverCfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := serverEng.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = serverEng.Close() })

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort(fmt.Sprintf("%s:%d", serverHost, echoPort)))
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
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()

	// Create and configure a real kernel TUN device.
	tunMgr, err := hosttun.Create(hosttun.Options{Name: "uwgtest%d", MTU: 1420})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tunMgr.Close() })

	tunAddr := netip.MustParsePrefix(clientWGAddr)
	serverRoute := netip.MustParsePrefix(serverWGAddr)
	if err := hosttun.Configure(tunMgr, hosttun.Options{
		Name:      tunMgr.Name(),
		MTU:       1420,
		Configure: true,
		Addresses: []netip.Prefix{tunAddr},
		Routes:    []netip.Prefix{serverRoute},
	}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = tunMgr.RemoveRoute(serverRoute)
		_ = tunMgr.RemoveAddress(tunAddr)
	})

	// Inject the real TUN manager into the engine startup path.
	oldCreate := createHostTUNManager
	createHostTUNManager = func(opts hosttun.Options) (hosttun.Manager, error) {
		return tunMgr, nil
	}
	t.Cleanup(func() { createHostTUNManager = oldCreate })

	// Client engine: WG + real TUN, peer = server.
	dropIPv4Invalid := false
	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{clientWGAddr}
	clientCfg.TUN.Enabled = true
	clientCfg.TUN.Name = tunMgr.Name()
	clientCfg.Filtering.DropIPv4Invalid = &dropIPv4Invalid
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{serverWGAddr},
		PersistentKeepalive: 1,
	}}
	if err := clientCfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	clientEng, err := New(clientCfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := clientEng.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = clientEng.Close() })

	// Poll until the WireGuard handshake completes (PersistentKeepalive fires
	// within 1 s on a warm host; cold Docker containers can take 8–10 s).
	deadline := time.Now().Add(15 * time.Second)
	for {
		st, err := clientEng.Status()
		if err == nil {
			for _, p := range st.Peers {
				if p.HasHandshake {
					goto handshakeDone
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("WireGuard handshake did not complete within 15 s")
		}
		time.Sleep(250 * time.Millisecond)
	}
handshakeDone:

	// Dial from this process through the real TUN device: the kernel routes
	// packets to 198.19.1.1 via the TUN interface, the engine picks them up,
	// encrypts and sends via WG UDP to the server engine, which echoes back.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", serverHost, echoPort))
	if err != nil {
		t.Fatalf("dial through real TUN: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	const msg = "real-tun-e2e"
	if _, err := conn.Write([]byte(msg)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read through real TUN: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("TUN e2e echo mismatch: got %q", buf)
	}
}
