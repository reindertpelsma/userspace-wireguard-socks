// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
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
			MeshTrust:      config.MeshTrustTrustedAlways,
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
	if peers[0].PublicKey != client2Key.PublicKey().String() || peers[0].Endpoint == "" || len(peers[0].AllowedIPs) != 1 || peers[0].AllowedIPs[0] != "100.64.94.3/32" || peers[0].PSK == "" || peers[0].MeshTrust != string(config.MeshTrustTrustedAlways) {
		t.Fatalf("unexpected mesh peer: %+v", peers[0])
	}
}

func TestMeshAdvertisedEndpointByTransport(t *testing.T) {
	st := PeerStatus{Endpoint: "198.51.100.10:51820"}
	if got := meshAdvertisedEndpoint(config.Peer{}, st, nil, ""); got != st.Endpoint {
		t.Fatalf("legacy udp endpoint=%q want %q", got, st.Endpoint)
	}
	transports := []transport.Config{
		{Name: "udp", Base: "udp"},
		{Name: "turn-udp", Base: "turn", TURN: transport.TURNConfig{Protocol: "udp"}},
		{Name: "turn-tls", Base: "turn", TURN: transport.TURNConfig{Protocol: "tls"}},
		{Name: "web", Base: "https"},
	}
	if got := meshAdvertisedEndpoint(config.Peer{Transport: "udp"}, st, transports, ""); got != st.Endpoint {
		t.Fatalf("udp endpoint=%q want %q", got, st.Endpoint)
	}
	if got := meshAdvertisedEndpoint(config.Peer{Transport: "turn-udp"}, st, transports, ""); got != st.Endpoint {
		t.Fatalf("turn udp endpoint=%q want %q", got, st.Endpoint)
	}
	if got := meshAdvertisedEndpoint(config.Peer{Transport: "turn-tls"}, st, transports, ""); got != "" {
		t.Fatalf("turn tls endpoint=%q want empty", got)
	}
	if got := meshAdvertisedEndpoint(config.Peer{Transport: "web"}, st, transports, ""); got != "" {
		t.Fatalf("https endpoint=%q want empty", got)
	}
}

func TestMeshBearerTokenBindsServerStaticKey(t *testing.T) {
	serverKey := mustMeshKey(t)
	clientKey := mustMeshKey(t)
	curve := ecdh.X25519()
	challengePriv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	client := &meshControlClient{
		peer:       config.Peer{},
		privateKey: clientKey,
	}
	challenge := meshChallengeResponse{
		ServerPublicKey:    serverKey.PublicKey().String(),
		ChallengePublicKey: base64.StdEncoding.EncodeToString(challengePriv.PublicKey().Bytes()),
		TokenVersion:       meshTokenVersionV2,
		ExpiresUnix:        time.Now().Add(time.Minute).Unix(),
	}
	token, _, err := client.bearerToken(netip.MustParseAddrPort("100.64.99.2:0"), challenge)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil {
		t.Fatal(err)
	}
	if raw[0] != meshTokenVersionV2 {
		t.Fatalf("token version=%d want %d", raw[0], meshTokenVersionV2)
	}
	ephPub, err := curve.NewPublicKey(raw[1:33])
	if err != nil {
		t.Fatal(err)
	}
	body := raw[65 : len(raw)-32]

	rogueShared, err := challengePriv.ECDH(ephPub)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := meshOpen(body, rogueShared, meshAuthContextLabel); err == nil {
		t.Fatal("mesh auth body decrypted without server static key")
	}

	serverPriv, err := curve.NewPrivateKey(serverKey[:])
	if err != nil {
		t.Fatal(err)
	}
	staticShared, err := serverPriv.ECDH(ephPub)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := meshOpen(body, meshAuthKey(rogueShared, staticShared), meshAuthContextLabel)
	if err != nil {
		t.Fatal(err)
	}
	if got := wgtypes.Key(plain).String(); got != clientKey.PublicKey().String() {
		t.Fatalf("decrypted peer=%q want %q", got, clientKey.PublicKey().String())
	}
}

func TestMeshControlFetchChallengeLimitsBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/challenge" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"server_public_key":"`+strings.Repeat("A", meshChallengeBodyLimit*2)+`","challenge_public_key":"AQ==","expires_unix":1}`)
	}))
	defer server.Close()

	controlURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client := &meshControlClient{
		controlURL: controlURL,
		httpClient: server.Client(),
	}
	if _, err := client.fetchChallenge(context.Background()); err == nil {
		t.Fatal("expected oversized challenge response to fail")
	}
}

func TestApplyMeshDiscoveredPeersCapsDynamicPeers(t *testing.T) {
	parent := config.Peer{
		PublicKey:  "parent",
		AllowedIPs: []string{"10.1.0.0/16"},
	}
	eng := &Engine{
		cfg: config.Config{
			WireGuard: config.WireGuard{
				Peers: []config.Peer{parent},
			},
		},
		dynamicPeers: map[string]*dynamicPeer{
			"other-existing": {
				ParentPublicKey: "other",
				Peer: config.Peer{
					PublicKey:  "other-existing",
					AllowedIPs: []string{"192.0.2.1/32"},
				},
			},
		},
	}

	discovered := make([]meshDiscoveredPeer, 0, meshDynamicPeerLimit+32)
	for i := 0; i < meshDynamicPeerLimit+32; i++ {
		ip := netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
		discovered = append(discovered, meshDiscoveredPeer{
			PublicKey:  "peer-" + strconv.Itoa(i),
			AllowedIPs: []string{netip.PrefixFrom(ip, 32).String()},
		})
	}
	if err := eng.applyMeshDiscoveredPeers(parent, discovered); err != nil {
		t.Fatal(err)
	}
	if len(eng.dynamicPeers) != meshDynamicPeerLimit {
		t.Fatalf("dynamic peer count=%d want %d", len(eng.dynamicPeers), meshDynamicPeerLimit)
	}
	if eng.dynamicPeers["other-existing"] == nil {
		t.Fatal("existing non-parent dynamic peer was evicted")
	}
	parentCount := 0
	for _, dp := range eng.dynamicPeers {
		if dp != nil && dp.ParentPublicKey == parent.PublicKey {
			parentCount++
		}
	}
	if parentCount != meshDynamicPeerLimit-1 {
		t.Fatalf("parent dynamic peer count=%d want %d", parentCount, meshDynamicPeerLimit-1)
	}
}

func TestApplyMeshDiscoveredPeersReplacesStalePeersAtCapacity(t *testing.T) {
	parent := config.Peer{
		PublicKey:  "parent",
		AllowedIPs: []string{"10.2.0.0/16"},
	}
	eng := &Engine{
		cfg: config.Config{
			WireGuard: config.WireGuard{
				Peers: []config.Peer{parent},
			},
		},
		dynamicPeers: make(map[string]*dynamicPeer, meshDynamicPeerLimit),
	}
	for i := 0; i < meshDynamicPeerLimit; i++ {
		ip := netip.AddrFrom4([4]byte{10, 2, byte(i >> 8), byte(i)})
		eng.dynamicPeers["old-"+strconv.Itoa(i)] = &dynamicPeer{
			ParentPublicKey: parent.PublicKey,
			Peer: config.Peer{
				PublicKey:  "old-" + strconv.Itoa(i),
				AllowedIPs: []string{netip.PrefixFrom(ip, 32).String()},
			},
		}
	}

	discovered := make([]meshDiscoveredPeer, 0, meshDynamicPeerLimit)
	for i := 0; i < meshDynamicPeerLimit; i++ {
		ip := netip.AddrFrom4([4]byte{10, 2, byte((i + meshDynamicPeerLimit) >> 8), byte(i + meshDynamicPeerLimit)})
		discovered = append(discovered, meshDiscoveredPeer{
			PublicKey:  "new-" + strconv.Itoa(i),
			AllowedIPs: []string{netip.PrefixFrom(ip, 32).String()},
		})
	}
	if err := eng.applyMeshDiscoveredPeers(parent, discovered); err != nil {
		t.Fatal(err)
	}
	if len(eng.dynamicPeers) != meshDynamicPeerLimit {
		t.Fatalf("dynamic peer count=%d want %d", len(eng.dynamicPeers), meshDynamicPeerLimit)
	}
	if eng.dynamicPeers["new-0"] == nil {
		t.Fatal("new dynamic peer was not inserted at capacity")
	}
	if eng.dynamicPeers["old-0"] != nil {
		t.Fatal("stale dynamic peer was not removed")
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
	forceMeshDynamicActive(t, client1, client2Key.PublicKey().String())
	forceMeshDynamicActive(t, client2, client1Key.PublicKey().String())

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

	st1, err := client1.Status()
	if err != nil {
		t.Fatal(err)
	}
	if len(st1.DynamicPeers) != 1 || st1.DynamicPeers[0].PublicKey != client2Key.PublicKey().String() || st1.DynamicPeers[0].ParentPublicKey != serverKey.PublicKey().String() {
		t.Fatalf("unexpected dynamic peer status: %+v", st1.DynamicPeers)
	}

	before1 := peerCountersByKey(t, server, client1Key.PublicKey().String())
	before2 := peerCountersByKey(t, server, client2Key.PublicKey().String())

	conn := retryMeshDialContext(t, client1, "tcp", "100.64.95.3:18080", 30*time.Second)
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
	if meshPeerHasDirectHandshake(t, client1, client2Key.PublicKey().String()) && meshPeerHasDirectHandshake(t, client2, client1Key.PublicKey().String()) {
		if after1.ReceiveBytes-before1.ReceiveBytes >= uint64(len(payload)) || after2.TransmitBytes-before2.TransmitBytes >= uint64(len(payload)) {
			t.Fatalf("server relay counters grew like relayed traffic: before1=%+v after1=%+v before2=%+v after2=%+v", before1, after1, before2, after2)
		}
	} else {
		t.Logf("dynamic peer handshake not observed on both sides; skipping no-relay counter assertion")
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
	forceMeshDynamicActive(t, clientA, clientBKey.PublicKey().String())
	forceMeshDynamicActive(t, clientB, clientAKey.PublicKey().String())

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

	goodCtx, goodCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer goodCancel()
	conn, err := retryMeshDialContextWithContext(goodCtx, clientA, "tcp", "100.64.97.3:80", 30*time.Second)
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
		{
			Action:      acl.Allow,
			Source:      "100.64.98.0/24",
			Destination: "100.64.70.7/32",
			DestPort:    "443",
			Protocol:    "tcp",
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
	if len(resp.Inbound) != 2 {
		t.Fatalf("inbound ACL count=%d want 2: %+v", len(resp.Inbound), resp.Inbound)
	}
	if got := resp.Inbound[0].Destinations; len(got) != 1 || got[0] != "100.64.98.2/32" {
		t.Fatalf("first projected destinations=%v want [100.64.98.2/32]", got)
	}
	if got := resp.Inbound[1].Destinations; len(got) != 2 || got[0] != "100.64.98.128/25" || got[1] != "100.64.98.2/32" {
		t.Fatalf("wildcard projected destinations=%v want requester allowed prefixes", got)
	}
	if len(resp.Outbound) != 1 {
		t.Fatalf("outbound ACL count=%d want 1: %+v", len(resp.Outbound), resp.Outbound)
	}
	if got := resp.Outbound[0].Sources; len(got) != 2 || got[0] != "100.64.98.128/25" || got[1] != "100.64.98.2/32" {
		t.Fatalf("projected outbound sources=%v want requester allowed prefixes", got)
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

func forceMeshDynamicActive(t *testing.T, eng *Engine, publicKey string) {
	t.Helper()
	eng.dynamicMu.Lock()
	dp := eng.dynamicPeers[publicKey]
	if dp == nil {
		eng.dynamicMu.Unlock()
		t.Fatalf("dynamic peer %s not found", publicKey)
	}
	dp.Active = true
	eng.dynamicMu.Unlock()
	if err := eng.reconcileDynamicPeerPriority(); err != nil {
		t.Fatal(err)
	}
}

func meshPeerHasDirectHandshake(t *testing.T, eng *Engine, publicKey string) bool {
	t.Helper()
	st, err := eng.Status()
	if err != nil {
		t.Fatal(err)
	}
	for _, peer := range st.Peers {
		if peer.PublicKey == publicKey && peer.Dynamic && peer.HasHandshake {
			return true
		}
	}
	return false
}

func retryMeshDialContext(t *testing.T, eng *Engine, network, target string, timeout time.Duration) net.Conn {
	t.Helper()
	conn, err := retryMeshDialContextWithContext(context.Background(), eng, network, target, timeout)
	if err != nil {
		t.Fatal(err)
	}
	return conn
}

func retryMeshDialContextWithContext(ctx context.Context, eng *Engine, network, target string, timeout time.Duration) (net.Conn, error) {
	deadline := time.Now().Add(timeout)
	var last error
	for time.Now().Before(deadline) {
		attemptCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		conn, err := eng.DialContext(attemptCtx, network, target)
		cancel()
		if err == nil {
			return conn, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if last == nil {
		last = context.DeadlineExceeded
	}
	return nil, last
}

func TestMeshControlRateLimiter(t *testing.T) {
	called := 0
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called++
		w.WriteHeader(http.StatusOK)
	})
	handler := (&Engine{}).meshControlRateLimit(inner)

	hit := func(remote string) int {
		req := httptest.NewRequest(http.MethodGet, "/v1/challenge", nil)
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w.Result().StatusCode
	}

	// Burst budget for one source IP is meshControlBurst; the very next
	// request after the burst is exhausted must be rejected with 429.
	for i := 0; i < meshControlBurst; i++ {
		if got := hit("10.0.0.1:1234"); got != http.StatusOK {
			t.Fatalf("burst request %d/%d got status %d, want 200", i+1, meshControlBurst, got)
		}
	}
	if got := hit("10.0.0.1:5678"); got != http.StatusTooManyRequests {
		t.Fatalf("post-burst request got status %d, want 429 (rate limit)", got)
	}

	// A different source IP must have its own bucket — same connection
	// being rate-limited should not affect a fresh peer.
	if got := hit("10.0.0.2:1234"); got != http.StatusOK {
		t.Fatalf("fresh-peer request got status %d, want 200", got)
	}

	// Refill: at meshControlRequestsPerSecond (10) per second, 200ms gives
	// ~2 tokens back, so the next request from 10.0.0.1 should succeed.
	time.Sleep(250 * time.Millisecond)
	if got := hit("10.0.0.1:9999"); got != http.StatusOK {
		t.Fatalf("after refill, request from 10.0.0.1 got status %d, want 200", got)
	}

	if called == 0 {
		t.Fatal("inner handler was never reached; rate limiter is failing closed")
	}
}
