// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package uwgsocks_test

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"testing"
	"time"

	uwg "github.com/reindertpelsma/userspace-wireguard-socks"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLibraryHelloWorldTCP(t *testing.T) {
	serverKey := mustExampleKey(t)
	clientKey := mustExampleKey(t)
	serverPort := freeExampleUDPPort(t)

	serverCfg := uwg.DefaultConfig()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.77.1/32"}
	serverCfg.WireGuard.Peers = []uwg.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.77.2/32"},
	}}
	if err := serverCfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	server, err := uwg.New(serverCfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := server.Start(); err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	clientCfg := uwg.DefaultConfig()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.77.2/32"}
	clientCfg.WireGuard.Peers = []uwg.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            net.JoinHostPort("127.0.0.1", itoaExample(serverPort)),
		AllowedIPs:          []string{"100.64.77.1/32"},
		PersistentKeepalive: 1,
	}}
	if err := clientCfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	client, err := uwg.New(clientCfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Start(); err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	ln, err := server.ListenTCP(netip.MustParseAddrPort("100.64.77.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_, _ = c.Write([]byte("Hello World\n"))
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := client.DialTunnelContext(ctx, "tcp", "100.64.77.1:18080")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	got, err := io.ReadAll(conn)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "Hello World\n" {
		t.Fatalf("got %q", got)
	}
}

func mustExampleKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func freeExampleUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func itoaExample(v int) string {
	return fmt.Sprintf("%d", v)
}
