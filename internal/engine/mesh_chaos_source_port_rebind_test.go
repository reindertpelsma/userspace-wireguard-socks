// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite && !race

package engine

import (
	"net"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

// TestMeshChaosResume_SourcePortRebind pins the production code
// path that fires when a peer's apparent outbound source port
// changes mid-session — the canonical scenarios are:
//
//   - NAT-mapping ages out and the gateway picks a new external
//     port the next time the peer sends.
//   - The peer restarts (process crash + supervisor restart, or
//     explicit reconnect) and its kernel allocates a different
//     ephemeral source port.
//
// Both manifest the same way to the hub: a previously-known peer
// suddenly arrives from a new (IP,port). WireGuard's roaming
// behaviour MUST update the hub's stored endpoint, AND mesh-control
// MUST advertise the updated endpoint to other peers so they can
// reach the rebooted peer at its new address.
//
// Topology:
//
//	          ┌─────────────┐
//	          │     hub     │
//	          └──────┬──────┘
//	                 │
//	      ┌──────────┴───────────┐
//	      │                      │
//	   ┌──┴──┐               ┌───┴──┐
//	   │  A  │ port P1 ───►  │  B   │ (witness peer — polls mesh-
//	   └─────┘               └──────┘  control, observes A's
//	                                   advertised endpoint)
//
// Sequence:
//  1. Bring up hub, A on port P1, B (witness).
//  2. Wait for handshakes; mesh polling; verify A↔B relay traffic
//     works.
//  3. Snapshot A's endpoint as known to B (= hub's view of A,
//     advertised via mesh-control). Should be 127.0.0.1:P1.
//  4. Tear down A. Start A' with the SAME private key on a NEW
//     port P2 (P2 != P1). A' re-handshakes with hub from a fresh
//     ephemeral source.
//  5. Hub MUST roam its endpoint for A's pubkey from P1 → P2.
//  6. After B polls mesh-control again, B's DynamicPeers entry
//     for A MUST reflect the new port (P2).
//  7. A'↔B traffic via relay still works byte-exact.
//
// This is a less-extreme cousin of the relay-failover test: the
// direct path is fine throughout, only A's source port changes.
// The WG roaming + mesh-control re-advertise pipeline is what's
// under test.
//
// Wall time: ~10-30s (handshake + mesh poll cycle + transfer).
//
// Gated by UWGS_RUN_MESH_CHAOS=1; -short skips it.
func TestMeshChaosResume_SourcePortRebind(t *testing.T) {
	if testing.Short() {
		t.Skip("mesh chaos test skipped in -short mode")
	}
	if !testingChaosFlag() {
		t.Skip("set UWGS_RUN_MESH_CHAOS=1 to run source-port-rebind chaos test")
	}

	hubKey := mustMeshKey(t)
	keyA := mustMeshKey(t)
	keyB := mustMeshKey(t)
	hubPort := freeUDPPortTest(t)

	pskA := mustMeshKey(t).String()
	pskB := mustMeshKey(t).String()

	hubCfg := config.Default()
	hubCfg.WireGuard.PrivateKey = hubKey.String()
	hubCfg.WireGuard.ListenPort = &hubPort
	hubCfg.WireGuard.Addresses = []string{"100.64.101.1/32"}
	hubCfg.MeshControl.Listen = "100.64.101.1:8803"
	relay := true
	hubCfg.Relay.Enabled = &relay
	hubCfg.ACL.RelayDefault = acl.Allow
	hubCfg.WireGuard.Peers = []config.Peer{
		{
			PublicKey:      keyA.PublicKey().String(),
			PresharedKey:   pskA,
			AllowedIPs:     []string{"100.64.101.2/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
		{
			PublicKey:      keyB.PublicKey().String(),
			PresharedKey:   pskB,
			AllowedIPs:     []string{"100.64.101.3/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
	}
	hub := mustStartMeshEngine(t, hubCfg)
	defer hub.Close()

	clientCfg := func(priv string, addr, otherAddr, psk string, listenPort int) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = priv
		cfg.WireGuard.ListenPort = &listenPort
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           hubKey.PublicKey().String(),
			PresharedKey:        psk,
			Endpoint:            "127.0.0.1:" + portStr(hubPort),
			AllowedIPs:          []string{"100.64.101.1/32", otherAddr},
			PersistentKeepalive: 1,
			ControlURL:          "http://100.64.101.1:8803",
			MeshEnabled:         true,
			MeshAcceptACLs:      true,
		}}
		return cfg
	}

	portA1 := freeUDPPortTest(t)
	portB := freeUDPPortTest(t)

	engA := mustStartMeshEngine(t, clientCfg(
		keyA.String(), "100.64.101.2/32", "100.64.101.3/32", pskA, portA1,
	))
	engB := mustStartMeshEngine(t, clientCfg(
		keyB.String(), "100.64.101.3/32", "100.64.101.2/32", pskB, portB,
	))
	defer engB.Close()

	waitPeerHandshakeTest(t, hub, keyA.PublicKey().String())
	waitPeerHandshakeTest(t, hub, keyB.PublicKey().String())
	waitPeerHandshakeTest(t, engA, hubKey.PublicKey().String())
	waitPeerHandshakeTest(t, engB, hubKey.PublicKey().String())

	// Mesh discovery on B (the witness peer).
	engB.runMeshPolling()
	waitDynamicPeerStatus(t, engB, keyA.PublicKey().String())

	// Verify hub learned A at port P1.
	hubBeforeA := lookupPeerEndpoint(t, hub, keyA.PublicKey().String())
	if !endpointPortEquals(hubBeforeA, portA1) {
		t.Fatalf("hub's endpoint for A before rebind = %q; want port %d", hubBeforeA, portA1)
	}
	// And B learned the same address via mesh-control.
	bBeforeA := lookupDynamicPeerEndpoint(t, engB, keyA.PublicKey().String())
	if !endpointPortEquals(bBeforeA, portA1) {
		t.Fatalf("B's mesh-learned endpoint for A before rebind = %q; want port %d", bBeforeA, portA1)
	}

	// Baseline relay traffic: B → A via relay (hub). Must work.
	const blobBytes = 256 * 1024 // 256 KiB — small, this isn't a throughput test
	stopFn := startBlobServerOn(t, engA, "100.64.101.2:18080", 0, 1, blobBytes)
	if err := fetchBlobAndVerify(engB, "100.64.101.2:18080", 0, 1, blobBytes); err != nil {
		stopFn()
		engA.Close()
		t.Fatalf("baseline B→A pre-rebind transfer failed: %v", err)
	}
	stopFn()

	// === Rebind ===
	// Tear down A. Start A' with the SAME private key on a NEW
	// port. The kernel will pick a fresh ephemeral source for the
	// new WG socket. Hub MUST observe this and roam.
	engA.Close()

	// Wait briefly for hub's WG to notice A is gone (no point
	// rushing — the rebind exercise should validate roaming, not
	// race with cleanup state).
	time.Sleep(500 * time.Millisecond)

	portA2 := freeUDPPortTest(t)
	if portA2 == portA1 {
		// Astronomically unlikely (port-allocator returns the
		// next free, A1 is now closed but typically the kernel
		// rotates) but if the test gets unlucky, just retry.
		portA2 = freeUDPPortTest(t)
		if portA2 == portA1 {
			t.Skip("freeUDPPortTest returned the same port twice; can't simulate a rebind")
		}
	}
	engA = mustStartMeshEngine(t, clientCfg(
		keyA.String(), "100.64.101.2/32", "100.64.101.3/32", pskA, portA2,
	))
	defer engA.Close()

	waitPeerHandshakeTest(t, hub, keyA.PublicKey().String())
	waitPeerHandshakeTest(t, engA, hubKey.PublicKey().String())

	// Hub MUST roam: its endpoint for A's pubkey is now port P2.
	// WG-go updates the endpoint on the first authenticated packet
	// from the new source, so by the time waitPeerHandshakeTest
	// returns we should already see the new port. Allow a small
	// window for the IpcGet to settle.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ep := lookupPeerEndpoint(t, hub, keyA.PublicKey().String()); endpointPortEquals(ep, portA2) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	hubAfterA := lookupPeerEndpoint(t, hub, keyA.PublicKey().String())
	if !endpointPortEquals(hubAfterA, portA2) {
		t.Fatalf("hub did not roam: endpoint for A after rebind = %q; want port %d (was %d)", hubAfterA, portA2, portA1)
	}

	// B re-polls mesh-control. Its DynamicPeers entry for A must
	// reflect the new port. (mesh-control advertises hub's view of
	// each peer, so as soon as hub roamed, the next /v1/peers
	// response should carry the new address.)
	deadline = time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		engB.runMeshPolling()
		if ep := lookupDynamicPeerEndpoint(t, engB, keyA.PublicKey().String()); endpointPortEquals(ep, portA2) {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	bAfterA := lookupDynamicPeerEndpoint(t, engB, keyA.PublicKey().String())
	if !endpointPortEquals(bAfterA, portA2) {
		t.Fatalf("B's mesh-learned endpoint for A after rebind = %q; want port %d (mesh-control didn't re-advertise)", bAfterA, portA2)
	}

	// Final invariant: B → A relay traffic still works after the
	// rebind. This is the bytes-flow proof that the whole roaming
	// + re-advertise pipeline didn't strand traffic somewhere.
	stopFn = startBlobServerOn(t, engA, "100.64.101.2:18080", 0, 1, blobBytes)
	defer stopFn()
	if err := fetchBlobAndVerify(engB, "100.64.101.2:18080", 0, 1, blobBytes); err != nil {
		t.Fatalf("post-rebind B→A transfer failed: %v", err)
	}

	t.Logf("source-port rebind: A reconnected from port %d → %d; hub roamed; mesh-control re-advertised; B→A relay traffic byte-exact",
		portA1, portA2)
}

// lookupPeerEndpoint returns the hub-side WG endpoint observed for
// the given peer pubkey, or "" if the peer is unknown.
func lookupPeerEndpoint(t *testing.T, eng *Engine, publicKey string) string {
	t.Helper()
	st, err := eng.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	for _, p := range st.Peers {
		if p.PublicKey == publicKey {
			return p.Endpoint
		}
	}
	return ""
}

// lookupDynamicPeerEndpoint returns the mesh-control-advertised
// endpoint a peer holds for one of its dynamic peers.
func lookupDynamicPeerEndpoint(t *testing.T, eng *Engine, publicKey string) string {
	t.Helper()
	st, err := eng.Status()
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	for _, p := range st.DynamicPeers {
		if p.PublicKey == publicKey {
			return p.Endpoint
		}
	}
	return ""
}

// endpointPortEquals returns true if `endpoint` parses as a
// host:port and the port matches `port`. We compare by port
// because the host is always 127.0.0.1 in these tests but the
// transport-prefix form ("trname@host:port") may be in play
// elsewhere; checking port is the simplest robust assertion.
func endpointPortEquals(endpoint string, port int) bool {
	if endpoint == "" {
		return false
	}
	// Strip any "transport-name@" prefix.
	if idx := indexByte(endpoint, '@'); idx >= 0 {
		endpoint = endpoint[idx+1:]
	}
	_, p, err := net.SplitHostPort(endpoint)
	if err != nil {
		return false
	}
	return p == portStr(port)
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func portStr(p int) string {
	// strconv.Itoa-equivalent without pulling strconv just here;
	// strconv is imported elsewhere in this package, so reuse via
	// the existing intToStr helper (see mesh_5peer_chaos_test.go).
	return intToStr(p)
}
