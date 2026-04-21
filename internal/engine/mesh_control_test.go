// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package engine

import (
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestMeshControlPeersRequiresAuthAndReturnsEncryptedPeers(t *testing.T) {
	serverKey := mustMeshKey(t)
	client1Key := mustMeshKey(t)
	client2Key := mustMeshKey(t)
	serverPort := freeUDPPortTest(t)

	serverCfg := config.Default()
	serverCfg.MeshControl.Listen = "100.64.94.1:8787"
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.94.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{
		{
			PublicKey:      client1Key.PublicKey().String(),
			PresharedKey:   mustMeshKey(t).String(),
			AllowedIPs:     []string{"100.64.94.2/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
		{
			PublicKey:      client2Key.PublicKey().String(),
			PresharedKey:   mustMeshKey(t).String(),
			AllowedIPs:     []string{"100.64.94.3/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
	}
	server := mustStartMeshEngine(t, serverCfg)
	defer server.Close()

	clientCfg := func(key wgtypes.Key, addr string, psk string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = key.String()
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           serverKey.PublicKey().String(),
			PresharedKey:        psk,
			Endpoint:            "127.0.0.1:" + strconv.Itoa(serverPort),
			AllowedIPs:          []string{"100.64.94.1/32"},
			PersistentKeepalive: 1,
			ControlURL:          "http://100.64.94.1:8787",
			MeshEnabled:         true,
			MeshAcceptACLs:      true,
		}}
		return cfg
	}

	client1 := mustStartMeshEngine(t, clientCfg(client1Key, "100.64.94.2/32", serverCfg.WireGuard.Peers[0].PresharedKey))
	defer client1.Close()
	client2 := mustStartMeshEngine(t, clientCfg(client2Key, "100.64.94.3/32", serverCfg.WireGuard.Peers[1].PresharedKey))
	defer client2.Close()

	waitPeerHandshakeTest(t, server, client1Key.PublicKey().String())
	waitPeerHandshakeTest(t, server, client2Key.PublicKey().String())
	waitPeerHandshakeTest(t, client1, serverKey.PublicKey().String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	httpClient := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return client1.DialTunnelContext(ctx, network, addr)
			},
		},
	}
	resp, err := httpClient.Get("http://100.64.94.1:8787/v1/peers")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated mesh peers status=%d want %d", resp.StatusCode, http.StatusUnauthorized)
	}

	controlPeer := client1.Peers()[0]
	meshClient, err := client1.newMeshControlClient(ctx, controlPeer)
	if err != nil {
		t.Fatal(err)
	}
	peers, err := meshClient.fetchPeers(ctx, netip.MustParseAddrPort("100.64.94.2:0"))
	if err != nil {
		t.Fatal(err)
	}
	if len(peers) != 1 {
		t.Fatalf("mesh peers len=%d want 1: %+v", len(peers), peers)
	}
	if peers[0].PublicKey != client2Key.PublicKey().String() || peers[0].Endpoint == "" || len(peers[0].AllowedIPs) != 1 || peers[0].AllowedIPs[0] != "100.64.94.3/32" || peers[0].PSK == "" {
		t.Fatalf("unexpected mesh peer: %+v", peers[0])
	}
}

func TestMeshControlPollingLearnsDynamicPeersAndActivatesDirectRoute(t *testing.T) {
	serverKey := mustMeshKey(t)
	client1Key := mustMeshKey(t)
	client2Key := mustMeshKey(t)
	serverPort := freeUDPPortTest(t)

	serverCfg := config.Default()
	serverCfg.MeshControl.Listen = "100.64.95.1:8787"
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.95.1/32"}
	relay := true
	serverCfg.Relay.Enabled = &relay
	serverCfg.ACL.RelayDefault = acl.Allow
	serverCfg.WireGuard.Peers = []config.Peer{
		{
			PublicKey:      client1Key.PublicKey().String(),
			PresharedKey:   mustMeshKey(t).String(),
			AllowedIPs:     []string{"100.64.95.2/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
		{
			PublicKey:      client2Key.PublicKey().String(),
			PresharedKey:   mustMeshKey(t).String(),
			AllowedIPs:     []string{"100.64.95.3/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
	}
	server := mustStartMeshEngine(t, serverCfg)
	defer server.Close()

	clientCfg := func(key wgtypes.Key, addr, other, psk string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = key.String()
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           serverKey.PublicKey().String(),
			PresharedKey:        psk,
			Endpoint:            "127.0.0.1:" + strconv.Itoa(serverPort),
			AllowedIPs:          []string{"100.64.95.1/32", other},
			PersistentKeepalive: 1,
			ControlURL:          "http://100.64.95.1:8787",
			MeshEnabled:         true,
			MeshAcceptACLs:      true,
		}}
		return cfg
	}

	client1 := mustStartMeshEngine(t, clientCfg(client1Key, "100.64.95.2/32", "100.64.95.3/32", serverCfg.WireGuard.Peers[0].PresharedKey))
	defer client1.Close()
	client2 := mustStartMeshEngine(t, clientCfg(client2Key, "100.64.95.3/32", "100.64.95.2/32", serverCfg.WireGuard.Peers[1].PresharedKey))
	defer client2.Close()

	waitPeerHandshakeTest(t, server, client1Key.PublicKey().String())
	waitPeerHandshakeTest(t, server, client2Key.PublicKey().String())
	waitPeerHandshakeTest(t, client1, serverKey.PublicKey().String())
	waitPeerHandshakeTest(t, client2, serverKey.PublicKey().String())

	client1.runMeshPolling()
	client2.runMeshPolling()
	waitDynamicPeerStatus(t, client1, client2Key.PublicKey().String())
	waitDynamicPeerStatus(t, client2, client1Key.PublicKey().String())
	waitMeshDynamicActive(t, client1, client2Key.PublicKey().String())
	waitMeshDynamicActive(t, client2, client1Key.PublicKey().String())
	st1, err := client1.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st1.DynamicPeers) != 1 || st1.DynamicPeers[0].PublicKey != client2Key.PublicKey().String() || st1.DynamicPeers[0].ParentPublicKey != serverKey.PublicKey().String() || !st1.DynamicPeers[0].Active {
		t.Fatalf("unexpected dynamic peer status: %+v", st1.DynamicPeers)
	}

	ln, err := client2.ListenTCP(netip.MustParseAddrPort("100.64.95.3:18080"))
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
		_, _ = io.Copy(conn, conn)
	}()

	before1 := peerCountersByKey(t, server, client1Key.PublicKey().String())
	before2 := peerCountersByKey(t, server, client2Key.PublicKey().String())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := client1.DialContext(ctx, "tcp", "100.64.95.3:18080")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	payload := bytes.Repeat([]byte("mesh-direct"), 512)
	if _, err := conn.Write(payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("mesh direct echo mismatch")
	}

	after1 := peerCountersByKey(t, server, client1Key.PublicKey().String())
	after2 := peerCountersByKey(t, server, client2Key.PublicKey().String())
	if after1.ReceiveBytes-before1.ReceiveBytes >= uint64(len(payload)) || after2.TransmitBytes-before2.TransmitBytes >= uint64(len(payload)) {
		t.Fatalf("server relay counters grew like relayed traffic: before1=%+v after1=%+v before2=%+v after2=%+v", before1, after1, before2, after2)
	}
}

func TestMeshControlSkipsPeersWithoutLocalACLCapability(t *testing.T) {
	serverKey := mustMeshKey(t)
	client1Key := mustMeshKey(t)
	client2Key := mustMeshKey(t)
	serverPort := freeUDPPortTest(t)

	serverCfg := config.Default()
	serverCfg.MeshControl.Listen = "100.64.96.1:8787"
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.96.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{
		{
			PublicKey:      client1Key.PublicKey().String(),
			PresharedKey:   mustMeshKey(t).String(),
			AllowedIPs:     []string{"100.64.96.2/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
		{
			PublicKey:      client2Key.PublicKey().String(),
			PresharedKey:   mustMeshKey(t).String(),
			AllowedIPs:     []string{"100.64.96.3/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: false,
		},
	}
	server := mustStartMeshEngine(t, serverCfg)
	defer server.Close()

	clientCfg := func(key wgtypes.Key, addr, other, psk string, accept bool) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = key.String()
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           serverKey.PublicKey().String(),
			PresharedKey:        psk,
			Endpoint:            "127.0.0.1:" + strconv.Itoa(serverPort),
			AllowedIPs:          []string{"100.64.96.1/32", other},
			PersistentKeepalive: 1,
			ControlURL:          "http://100.64.96.1:8787",
			MeshEnabled:         true,
			MeshAcceptACLs:      accept,
		}}
		return cfg
	}

	client1 := mustStartMeshEngine(t, clientCfg(client1Key, "100.64.96.2/32", "100.64.96.3/32", serverCfg.WireGuard.Peers[0].PresharedKey, true))
	defer client1.Close()
	client2 := mustStartMeshEngine(t, clientCfg(client2Key, "100.64.96.3/32", "100.64.96.2/32", serverCfg.WireGuard.Peers[1].PresharedKey, false))
	defer client2.Close()

	waitPeerHandshakeTest(t, server, client1Key.PublicKey().String())
	waitPeerHandshakeTest(t, server, client2Key.PublicKey().String())
	waitPeerHandshakeTest(t, client1, serverKey.PublicKey().String())

	client1.runMeshPolling()
	if st, err := client1.Status(); err != nil {
		t.Fatal(err)
	} else if len(st.DynamicPeers) != 0 {
		t.Fatalf("non-ACL-capable remote was unexpectedly learned as dynamic peer: %+v", st.DynamicPeers)
	}
	client2.runMeshPolling()
	if st, err := client2.Status(); err != nil {
		t.Fatal(err)
	} else if len(st.DynamicPeers) != 0 {
		t.Fatalf("non-ACL-capable requester unexpectedly learned dynamic peers: %+v", st.DynamicPeers)
	}
}

func TestMeshDynamicACLBlocksSpoofedReverseAndAllowsLegitFlow(t *testing.T) {
	serverKey := mustMeshKey(t)
	clientAKey := mustMeshKey(t)
	clientBKey := mustMeshKey(t)
	serverPort := freeUDPPortTest(t)

	serverCfg := config.Default()
	serverCfg.MeshControl.Listen = "100.64.97.1:8787"
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.97.1/32"}
	relay := true
	serverCfg.Relay.Enabled = &relay
	serverCfg.ACL.RelayDefault = acl.Deny
	serverCfg.ACL.Relay = []acl.Rule{{
		Action:      acl.Allow,
		Source:      "100.64.97.2/32",
		Destination: "100.64.97.3/32",
		DestPort:    "80",
		Protocol:    "tcp",
	}}
	serverCfg.WireGuard.Peers = []config.Peer{
		{
			PublicKey:      clientAKey.PublicKey().String(),
			PresharedKey:   mustMeshKey(t).String(),
			AllowedIPs:     []string{"100.64.97.2/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
		{
			PublicKey:      clientBKey.PublicKey().String(),
			PresharedKey:   mustMeshKey(t).String(),
			AllowedIPs:     []string{"100.64.97.3/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
	}
	server := mustStartMeshEngine(t, serverCfg)
	defer server.Close()

	clientCfg := func(key wgtypes.Key, addr, other, psk string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = key.String()
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           serverKey.PublicKey().String(),
			PresharedKey:        psk,
			Endpoint:            "127.0.0.1:" + strconv.Itoa(serverPort),
			AllowedIPs:          []string{"100.64.97.1/32", other},
			PersistentKeepalive: 1,
			ControlURL:          "http://100.64.97.1:8787",
			MeshEnabled:         true,
			MeshAcceptACLs:      true,
		}}
		return cfg
	}

	clientA := mustStartMeshEngine(t, clientCfg(clientAKey, "100.64.97.2/32", "100.64.97.3/32", serverCfg.WireGuard.Peers[0].PresharedKey))
	defer clientA.Close()
	clientB := mustStartMeshEngine(t, clientCfg(clientBKey, "100.64.97.3/32", "100.64.97.2/32", serverCfg.WireGuard.Peers[1].PresharedKey))
	defer clientB.Close()

	waitPeerHandshakeTest(t, server, clientAKey.PublicKey().String())
	waitPeerHandshakeTest(t, server, clientBKey.PublicKey().String())
	waitPeerHandshakeTest(t, clientA, serverKey.PublicKey().String())
	waitPeerHandshakeTest(t, clientB, serverKey.PublicKey().String())

	clientA.runMeshPolling()
	clientB.runMeshPolling()
	waitDynamicPeerStatus(t, clientA, clientBKey.PublicKey().String())
	waitDynamicPeerStatus(t, clientB, clientAKey.PublicKey().String())
	waitMeshDynamicActive(t, clientA, clientBKey.PublicKey().String())
	waitMeshDynamicActive(t, clientB, clientAKey.PublicKey().String())

	blockedLn, err := clientA.ListenTCP(netip.MustParseAddrPort("100.64.97.2:18081"))
	if err != nil {
		t.Fatal(err)
	}
	defer blockedLn.Close()
	blockedAccept := make(chan error, 1)
	go func() {
		conn, err := blockedLn.Accept()
		if err == nil {
			conn.Close()
			blockedAccept <- nil
			return
		}
		blockedAccept <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	malicious, err := clientB.net.DialContextTCPAddrPortWithBind(ctx, netip.MustParseAddrPort("100.64.97.3:80"), netip.MustParseAddrPort("100.64.97.2:18081"))
	if err == nil {
		malicious.Close()
	}
	select {
	case err := <-blockedAccept:
		if err == nil {
			t.Fatal("spoofed reverse flow unexpectedly reached destination listener")
		}
	case <-time.After(600 * time.Millisecond):
	}

	allowedLn, err := clientB.ListenTCP(netip.MustParseAddrPort("100.64.97.3:80"))
	if err != nil {
		t.Fatal(err)
	}
	defer allowedLn.Close()
	go func() {
		conn, err := allowedLn.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = io.Copy(conn, conn)
	}()

	goodCtx, goodCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer goodCancel()
	conn, err := clientA.DialContext(goodCtx, "tcp", "100.64.97.3:80")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	msg := []byte("allowed-mesh-acl")
	if _, err := conn.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatalf("allowed flow echo mismatch: got %q", got)
	}
}

func TestMeshACLsForRequesterProjectsDestinationsToRequesterSpace(t *testing.T) {
	serverKey := mustMeshKey(t)
	clientKey := mustMeshKey(t)
	serverPort := freeUDPPortTest(t)

	serverCfg := config.Default()
	serverCfg.MeshControl.Listen = "100.64.98.1:8787"
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.98.1/32"}
	serverCfg.ACL.RelayDefault = acl.Deny
	serverCfg.ACL.Relay = []acl.Rule{
		{
			Action:       acl.Allow,
			Source:       "100.64.50.0/24",
			Destinations: []string{"100.64.98.2/32", "100.64.99.0/24"},
			DestPort:     "80",
			Protocol:     "tcp",
		},
		{
			Action:   acl.Allow,
			Source:   "100.64.60.0/24",
			DestPort: "53",
			Protocol: "udp",
		},
	}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:      clientKey.PublicKey().String(),
		PresharedKey:   mustMeshKey(t).String(),
		AllowedIPs:     []string{"100.64.98.2/32", "100.64.98.128/25"},
		MeshEnabled:    true,
		MeshAcceptACLs: true,
	}}

	server := mustStartMeshEngine(t, serverCfg)
	defer server.Close()

	resp, err := server.meshACLsForRequester(clientKey.PublicKey().String())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Relay) != 2 {
		t.Fatalf("relay ACL count=%d want 2: %+v", len(resp.Relay), resp.Relay)
	}
	if got := resp.Relay[0].Destinations; len(got) != 1 || got[0] != "100.64.98.2/32" {
		t.Fatalf("first projected destinations=%v want [100.64.98.2/32]", got)
	}
	if got := resp.Relay[1].Destinations; len(got) != 2 || got[0] != "100.64.98.128/25" || got[1] != "100.64.98.2/32" {
		t.Fatalf("wildcard projected destinations=%v want requester allowed prefixes", got)
	}
}

func mustStartMeshEngine(t *testing.T, cfg config.Config) *Engine {
	t.Helper()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(); err != nil {
		t.Fatal(err)
	}
	return eng
}

func mustMeshKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func waitPeerHandshakeTest(t *testing.T, eng *Engine, publicKey string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, err := eng.Status()
		if err != nil {
			t.Fatal(err)
		}
		for _, peer := range st.Peers {
			if peer.PublicKey == publicKey && peer.HasHandshake {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for peer %s handshake", publicKey)
}

func waitDynamicPeerStatus(t *testing.T, eng *Engine, publicKey string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		st, err := eng.Status()
		if err != nil {
			t.Fatal(err)
		}
		for _, peer := range st.Peers {
			if peer.PublicKey == publicKey && peer.Dynamic {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for dynamic peer %s", publicKey)
}

func waitMeshDynamicActive(t *testing.T, eng *Engine, publicKey string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		eng.refreshDynamicPeerActivity()
		st, err := eng.Status()
		if err != nil {
			t.Fatal(err)
		}
		for _, peer := range st.Peers {
			if peer.PublicKey == publicKey && peer.Dynamic && peer.MeshActive && peer.HasHandshake {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for active dynamic peer %s", publicKey)
}

func peerCountersByKey(t *testing.T, eng *Engine, publicKey string) PeerStatus {
	t.Helper()
	st, err := eng.Status()
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range st.Peers {
		if peer.PublicKey == publicKey {
			return peer
		}
	}
	t.Fatalf("peer %s not found in status", publicKey)
	return PeerStatus{}
}

func freeUDPPortTest(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}
