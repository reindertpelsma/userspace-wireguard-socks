// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

// TestMeshChaosResume_AdvertisedEndpointThroughNAT exercises the
// production-real code path where mesh-control advertises the
// NAT-translated source address each peer was observed coming from
// (rather than its locally-configured WG bind addr) and other peers
// learn that translated address as the dynamic-peer Endpoint.
//
// Topology (3 peers + chaos):
//
//	     hub (100.64.99.1, mesh-control + relay)
//	    /                                       \
//	chaosProxyA  (NAT for A→hub)            chaosProxyB  (NAT for B→hub)
//	   |                                          |
//	  A (100.64.99.2)                          B (100.64.99.3)
//
// Each client's WG endpoint for the hub is its own chaosProxy.
// The hub therefore sees A's source address as proxyA.Addr and B's
// as proxyB.Addr — precisely the NAT-mapping behavior production
// runs into. Because the mesh-control advertised endpoint comes
// from PeerStatus.Endpoint (the learned WG source), A's published
// "where to reach me" is proxyA.Addr.
//
// What this test pins:
//
//  1. PeerStatus.Endpoint on the hub equals proxyA.Addr / proxyB.Addr —
//     not the configured local WG bind. (The hub learned the proxy
//     addresses from inbound packets, exactly as a real NAT-mapped
//     peer would appear.)
//  2. After mesh-control polling, A's DynamicPeers[B].Endpoint and
//     B's DynamicPeers[A].Endpoint are the corresponding proxy
//     addresses (i.e., the hub forwarded the learned NAT mapping
//     to the other peer via /v1/peers).
//  3. Under chaos on BOTH access links (5%/20ms loss+jitter on
//     proxyA AND proxyB simultaneously), relay-routed A↔B traffic
//     completes byte-exact. The relay path is:
//     A → proxyA → hub → proxyB → B  (encrypted WG outer)
//     so EVERY datagram crosses two lossy proxies in series.
//
// Why we don't also assert direct-P2P here: the chaosProxy is a
// fixed-upstream NAT (its forwarding table is populated by source-
// based reverse lookup, not by reading WG payload). When peer A's
// dp.Active flips true and A starts WG-encapping packets to its
// learned-direct-endpoint = proxyB.Addr, proxyB forwards them to
// its upstream — which is the HUB, not B. Proper direct-P2P chaos
// requires a smarter proxy that NATs per-(src,dst) pair; that's a
// follow-up commit. The relay path under access-link chaos is
// already a load-bearing production scenario worth pinning.
//
// Gated by UWGS_RUN_MESH_CHAOS=1 + -short skips it.
func TestMeshChaosResume_AdvertisedEndpointThroughNAT(t *testing.T) {
	if testing.Short() {
		t.Skip("mesh chaos test skipped in -short mode")
	}
	if !testingChaosFlag() {
		t.Skip("set UWGS_RUN_MESH_CHAOS=1 to run advertised-endpoint chaos test")
	}

	hubKey := mustMeshKey(t)
	keyA := mustMeshKey(t)
	keyB := mustMeshKey(t)
	hubPort := freeUDPPortTest(t)

	// One chaosProxy per client → hub leg. Each forwards client→hub
	// outbound and hub→client replies (bidirectional via lastSrc).
	proxyA, err := startChaosProxy(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: hubPort},
		chaosPolicy{}, // start clean
	)
	if err != nil {
		t.Fatalf("start proxyA: %v", err)
	}
	defer proxyA.Close()
	proxyB, err := startChaosProxy(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: hubPort},
		chaosPolicy{},
	)
	if err != nil {
		t.Fatalf("start proxyB: %v", err)
	}
	defer proxyB.Close()

	pskA := mustMeshKey(t).String()
	pskB := mustMeshKey(t).String()

	// Hub: relay enabled, mesh-control listener, RelayDefault=Allow
	// so A↔B traffic via the hub isn't blocked by a static ACL.
	hubCfg := config.Default()
	hubCfg.WireGuard.PrivateKey = hubKey.String()
	hubCfg.WireGuard.ListenPort = &hubPort
	hubCfg.WireGuard.Addresses = []string{"100.64.99.1/32"}
	hubCfg.MeshControl.Listen = "100.64.99.1:8801"
	relay := true
	hubCfg.Relay.Enabled = &relay
	hubCfg.ACL.RelayDefault = acl.Allow
	hubCfg.WireGuard.Peers = []config.Peer{
		{
			PublicKey:      keyA.PublicKey().String(),
			PresharedKey:   pskA,
			AllowedIPs:     []string{"100.64.99.2/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
		{
			PublicKey:      keyB.PublicKey().String(),
			PresharedKey:   pskB,
			AllowedIPs:     []string{"100.64.99.3/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
	}
	hub := mustStartMeshEngine(t, hubCfg)
	defer hub.Close()

	clientCfg := func(priv, addr, otherAddr, psk, proxyAddr string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = priv
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           hubKey.PublicKey().String(),
			PresharedKey:        psk,
			Endpoint:            proxyAddr,
			AllowedIPs:          []string{"100.64.99.1/32", otherAddr},
			PersistentKeepalive: 1,
			ControlURL:          "http://100.64.99.1:8801",
			MeshEnabled:         true,
			MeshAcceptACLs:      true,
		}}
		return cfg
	}

	engA := mustStartMeshEngine(t, clientCfg(
		keyA.String(), "100.64.99.2/32", "100.64.99.3/32", pskA, proxyA.Addr().String(),
	))
	defer engA.Close()
	engB := mustStartMeshEngine(t, clientCfg(
		keyB.String(), "100.64.99.3/32", "100.64.99.2/32", pskB, proxyB.Addr().String(),
	))
	defer engB.Close()

	// Wait for handshakes through the (clean) proxies. If this hangs
	// we know the proxy itself isn't forwarding.
	waitPeerHandshakeTest(t, hub, keyA.PublicKey().String())
	waitPeerHandshakeTest(t, hub, keyB.PublicKey().String())
	waitPeerHandshakeTest(t, engA, hubKey.PublicKey().String())
	waitPeerHandshakeTest(t, engB, hubKey.PublicKey().String())

	// (1) Hub's view of A and B: source addr should be the proxy
	// listening port (NAT-translated), not the client's local WG bind.
	hubStatus, err := hub.Status()
	if err != nil {
		t.Fatalf("hub.Status: %v", err)
	}
	wantA := proxyA.Addr().String()
	wantB := proxyB.Addr().String()
	gotA := peerEndpointByKey(hubStatus.Peers, keyA.PublicKey().String())
	gotB := peerEndpointByKey(hubStatus.Peers, keyB.PublicKey().String())
	if !endpointMatches(gotA, wantA) {
		t.Fatalf("hub learned A's endpoint = %q; want match for proxyA = %q (NAT translation didn't take)", gotA, wantA)
	}
	if !endpointMatches(gotB, wantB) {
		t.Fatalf("hub learned B's endpoint = %q; want match for proxyB = %q", gotB, wantB)
	}

	// (2) Run mesh polling so A learns B (and vice versa) via the
	// hub's /v1/peers. The advertised endpoint each side receives
	// should be the OTHER side's NAT-translated addr.
	engA.runMeshPolling()
	engB.runMeshPolling()
	waitDynamicPeerStatus(t, engA, keyB.PublicKey().String())
	waitDynamicPeerStatus(t, engB, keyA.PublicKey().String())

	stA, err := engA.Status()
	if err != nil {
		t.Fatalf("engA.Status: %v", err)
	}
	stB, err := engB.Status()
	if err != nil {
		t.Fatalf("engB.Status: %v", err)
	}
	if got := dynamicEndpointByKey(stA.DynamicPeers, keyB.PublicKey().String()); !endpointMatches(got, wantB) {
		t.Fatalf("A's dynamic peer for B advertises endpoint=%q; want NAT-translated proxyB=%q", got, wantB)
	}
	if got := dynamicEndpointByKey(stB.DynamicPeers, keyA.PublicKey().String()); !endpointMatches(got, wantA) {
		t.Fatalf("B's dynamic peer for A advertises endpoint=%q; want NAT-translated proxyA=%q", got, wantA)
	}

	// (3) Flip BOTH access-link proxies to lossy. The relay path
	// A→hub→B now traverses two lossy hops. Combined per-RTT drop
	// is roughly 1 - (0.95)^4 ≈ 18.5% (4 traversals: A→pA, pA→hub,
	// hub→pB, pB→B for one direction, mirror for ack). That's
	// near the upper edge of what gVisor TCP can absorb without
	// retransmit-storm collapse, so we keep the rate modest.
	pol := chaosPolicy{LossRate: 0.05, Jitter: 20 * time.Millisecond}
	proxyA.SetPolicy(pol)
	proxyB.SetPolicy(pol)

	// Server side: B hosts an HTTP blob endpoint on its tunnel addr.
	const blobBytes = 4 * 1024 * 1024 // 4 MiB
	stopFn := startBlobServerOn(t, engB, "100.64.99.3:18080", 1 /*srcIdx*/, 0 /*dstIdx*/, blobBytes)
	defer stopFn()

	// Three relay-routed transfers under simultaneous chaos on
	// both access links. Each transfer crosses A→pA→hub→pB→B and
	// the ACKs/data go back the same way.
	const nTransfers = 3
	start := time.Now()
	for i := 0; i < nTransfers; i++ {
		if err := fetchBlobAndVerify(engA, "100.64.99.3:18080", 1, 0, blobBytes); err != nil {
			t.Fatalf("relay transfer %d under chaos failed: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	fwA, dropA, delayA := proxyA.Stats()
	fwB, dropB, delayB := proxyB.Stats()
	mb := float64(nTransfers*blobBytes) / (1 << 20)
	throughput := mb / elapsed.Seconds()
	t.Logf("relay-via-NAT chaos: %d × %d bytes = %.1f MiB through 5%%-loss+20ms-jitter on BOTH legs in %v (%.1f MiB/s); "+
		"proxyA fwd=%d drop=%d delayed=%d; proxyB fwd=%d drop=%d delayed=%d",
		nTransfers, blobBytes, mb, elapsed, throughput,
		fwA, dropA, delayA, fwB, dropB, delayB)
	if dropA == 0 || dropB == 0 {
		t.Errorf("expected loss policy to drop packets on BOTH proxies; got proxyA drop=%d proxyB drop=%d", dropA, dropB)
	}
}

// peerEndpointByKey returns the learned WG endpoint for a peer in
// the hub's status snapshot, or "" if the peer is not present.
func peerEndpointByKey(peers []PeerStatus, publicKey string) string {
	for _, p := range peers {
		if p.PublicKey == publicKey {
			return p.Endpoint
		}
	}
	return ""
}

// dynamicEndpointByKey returns the advertised (mesh-control-learned)
// endpoint a peer sees for one of its dynamic peers. "" if missing.
func dynamicEndpointByKey(dyn []DynamicPeerStatus, publicKey string) string {
	for _, p := range dyn {
		if p.PublicKey == publicKey {
			return p.Endpoint
		}
	}
	return ""
}

// endpointMatches compares "host:port" endpoints loosely: WireGuard
// reports "127.0.0.1:NNNN" but a mesh-control advertised endpoint
// might come back identically. We compare by parsed (host, port)
// so 127.0.0.1 <-> ::ffff:127.0.0.1 stays equivalent across stacks.
func endpointMatches(got, want string) bool {
	if got == "" || want == "" {
		return false
	}
	gh, gp, ok1 := splitHostPort(got)
	wh, wp, ok2 := splitHostPort(want)
	if !ok1 || !ok2 {
		return got == want
	}
	if gp != wp {
		return false
	}
	// Loopback equivalence across IPv4 / IPv4-in-IPv6.
	gh = strings.TrimPrefix(gh, "::ffff:")
	wh = strings.TrimPrefix(wh, "::ffff:")
	return gh == wh
}

func splitHostPort(s string) (string, string, bool) {
	h, p, err := net.SplitHostPort(s)
	if err != nil {
		return "", "", false
	}
	if _, err := strconv.Atoi(p); err != nil {
		return "", "", false
	}
	return h, p, true
}
