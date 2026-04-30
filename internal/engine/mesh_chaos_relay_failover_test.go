// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite && !race

package engine

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

// TestMeshChaosResume_RelayFailoverOn100PercentDrop pins the
// production code path that fires when a previously-direct WG
// path drops dead under sustained loss: the engine must notice
// (last-handshake-too-old → refreshDynamicPeerActivity flips
// dp.Active=false → reconcileDynamicPeerPriority de-prioritises
// the direct route) and traffic must transparently fail over to
// the relay (static parent peer) without manual intervention.
//
// This is THE failover invariant. If it breaks, deployments lose
// traffic when a NAT mapping ages out or a transit link goes
// silent — the wider relay fabric is the safety net for exactly
// this case.
//
// Topology:
//
//	      ┌──────────────┐
//	      │     hub      │ (relay enabled, mesh-control,
//	      └──────┬───────┘  RelayDefault=Allow)
//	             │
//	    ┌────────┴────────┐
//	    │                 │
//	┌───┴────┐        ┌───┴────┐
//	│ proxyA │        │ proxyB │  (per-client NAT to hub —
//	│↔ hub   │        │↔ hub   │   stays clean throughout the
//	└───┬────┘        └────┬───┘   test, ensures relay path
//	    │                  │       always remains usable)
//	  ┌─┴─┐              ┌─┴─┐
//	  │ A │──proxyDirAB──│ B │  (DIRECT path between A and B,
//	  └───┘              └───┘   chaos-controlled — flipped to
//	                             100% drop mid-test to trigger
//	                             relay-failover on both sides)
//
// Sequence:
//  1. Start hub + A + B with all three proxies clean.
//  2. WG handshakes establish via the hub-bound NAT proxies.
//  3. Mesh-control polling: A and B discover each other.
//  4. Override the discovered dynamic-peer Endpoint to
//     proxyDirectAB.Addr (mesh-control naturally advertised
//     proxyA/proxyB.Addr — those are NAT-mappings to hub, not
//     usable for A↔B direct). Force dp.Active=true.
//  5. Direct WG handshake completes via proxyDirectAB.
//  6. Verify direct A↔B TCP transfer works byte-exact.
//  7. Flip proxyDirectAB to 100% drop. Direct path dies.
//  8. Wait long enough for refreshDynamicPeerActivity (runs at
//     end of each 15s mesh poll) to observe handshake-age >
//     ActivePeerWindowSeconds (default 120s, matched to WG's
//     rekey timer). dp.Active should flip false on both A and B
//     within ~250-280s of the chaos flip — 120s (between-rekey
//     edge) + 120s (window) + 15s (poll cadence).
//  9. Run a tunnel transfer A↔B. Engine routes via relay (hub).
//     Must complete byte-exact — the failover happened.
//  10. Optional restoration phase: clear the chaos, wait for the
//     direct path to re-handshake, assert dp.Active=true again.
//
// Wall time: ~3-5 minutes (chaos detection budget is 280s plus
// ~30s of setup + transfers). Wait time is fundamentally bounded
// by wireguard-go's 120s rekey cycle — no shortcut available.
//
// Gated by UWGS_RUN_MESH_CHAOS=1; -short skips it.
func TestMeshChaosResume_RelayFailoverOn100PercentDrop(t *testing.T) {
	if testing.Short() {
		t.Skip("mesh chaos test skipped in -short mode")
	}
	if !testingChaosFlag() {
		t.Skip("set UWGS_RUN_MESH_CHAOS=1 or -uwgs-mesh-chaos to run relay-failover chaos test")
	}

	hubKey := mustMeshKey(t)
	keyA := mustMeshKey(t)
	keyB := mustMeshKey(t)
	hubPort := freeUDPPortTest(t)
	portA := freeUDPPortTest(t)
	portB := freeUDPPortTest(t)

	// Two NAT proxies: A↔hub and B↔hub. Stay clean — relay path
	// must remain usable throughout the test for failover to work.
	proxyAToHub, err := startChaosProxy(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: hubPort},
		chaosPolicy{},
	)
	if err != nil {
		t.Fatalf("start proxyAToHub: %v", err)
	}
	defer proxyAToHub.Close()
	proxyBToHub, err := startChaosProxy(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: hubPort},
		chaosPolicy{},
	)
	if err != nil {
		t.Fatalf("start proxyBToHub: %v", err)
	}
	defer proxyBToHub.Close()

	// Direct A↔B proxy. Bidirectional via lastSrc tracking. We
	// configure the upstream as B's WG port; A→B traffic forwards
	// there (recv src=A is non-upstream → forward to upstream=B),
	// B→A reply forwards back to A (recv src=B==upstream → forward
	// to lastSrc=A). This is the chokepoint we'll flip to 100%
	// drop to simulate a dead direct path.
	proxyDirectAB, err := startChaosProxy(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portB},
		chaosPolicy{},
	)
	if err != nil {
		t.Fatalf("start proxyDirectAB: %v", err)
	}
	defer proxyDirectAB.Close()

	pskA := mustMeshKey(t).String()
	pskB := mustMeshKey(t).String()

	// Hub: relay enabled, default ActivePeerWindowSeconds (120s).
	// Shorter values (e.g. 30s) interact badly with wireguard-go's
	// rekey cadence — LastHandshakeTime fluctuates above the
	// window between rekeys, so hub would intermittently stop
	// advertising peers and the client would drop them from its
	// dynamic-peer table. 120s is the smallest stable window for
	// this kind of test.
	hubCfg := config.Default()
	hubCfg.WireGuard.PrivateKey = hubKey.String()
	hubCfg.WireGuard.ListenPort = &hubPort
	hubCfg.WireGuard.Addresses = []string{"100.64.100.1/32"}
	hubCfg.MeshControl.Listen = "100.64.100.1:8802"
	relay := true
	hubCfg.Relay.Enabled = &relay
	hubCfg.ACL.RelayDefault = acl.Allow
	hubCfg.WireGuard.Peers = []config.Peer{
		{
			PublicKey:      keyA.PublicKey().String(),
			PresharedKey:   pskA,
			AllowedIPs:     []string{"100.64.100.2/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
		{
			PublicKey:      keyB.PublicKey().String(),
			PresharedKey:   pskB,
			AllowedIPs:     []string{"100.64.100.3/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
	}
	hub := mustStartMeshEngine(t, hubCfg)
	defer hub.Close()

	clientCfg := func(priv string, addr, otherAddr, psk, proxyHubAddr string, listenPort int) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = priv
		cfg.WireGuard.ListenPort = &listenPort
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           hubKey.PublicKey().String(),
			PresharedKey:        psk,
			Endpoint:            proxyHubAddr,
			AllowedIPs:          []string{"100.64.100.1/32", otherAddr},
			PersistentKeepalive: 1,
			ControlURL:          "http://100.64.100.1:8802",
			MeshEnabled:         true,
			MeshAcceptACLs:      true,
		}}
		return cfg
	}

	engA := mustStartMeshEngine(t, clientCfg(
		keyA.String(), "100.64.100.2/32", "100.64.100.3/32", pskA, proxyAToHub.Addr().String(), portA,
	))
	defer engA.Close()
	engB := mustStartMeshEngine(t, clientCfg(
		keyB.String(), "100.64.100.3/32", "100.64.100.2/32", pskB, proxyBToHub.Addr().String(), portB,
	))
	defer engB.Close()

	waitPeerHandshakeTest(t, hub, keyA.PublicKey().String())
	waitPeerHandshakeTest(t, hub, keyB.PublicKey().String())
	waitPeerHandshakeTest(t, engA, hubKey.PublicKey().String())
	waitPeerHandshakeTest(t, engB, hubKey.PublicKey().String())

	// Mesh discovery.
	engA.runMeshPolling()
	engB.runMeshPolling()
	waitDynamicPeerStatus(t, engA, keyB.PublicKey().String())
	waitDynamicPeerStatus(t, engB, keyA.PublicKey().String())

	// Override the mesh-control-advertised endpoint for the
	// direct path. Mesh-control gave us proxyA-to-hub.Addr (B's
	// NAT mapping to hub) — that proxy's upstream is hub, so it
	// can't actually carry direct A↔B traffic. The only proxy
	// that can is proxyDirectAB (with upstream=B).
	if err := forceMeshDynamicEndpoint(engA, keyB.PublicKey().String(), proxyDirectAB.Addr().String()); err != nil {
		t.Fatalf("override A's dynamic-peer-B endpoint: %v", err)
	}
	if err := forceMeshDynamicEndpoint(engB, keyA.PublicKey().String(), proxyDirectAB.Addr().String()); err != nil {
		t.Fatalf("override B's dynamic-peer-A endpoint: %v", err)
	}
	forceMeshDynamicActive(t, engA, keyB.PublicKey().String())
	forceMeshDynamicActive(t, engB, keyA.PublicKey().String())

	// Wait for the direct WG handshake to complete via proxyDirectAB.
	waitDynamicPeerHandshake(t, engA, keyB.PublicKey().String(), 30*time.Second)
	waitDynamicPeerHandshake(t, engB, keyA.PublicKey().String(), 30*time.Second)

	// Direct path is up — verify it actually carries TCP traffic.
	const blobBytes = 1 * 1024 * 1024 // 1 MiB
	stopFn := startBlobServerOn(t, engB, "100.64.100.3:18080", 1, 0, blobBytes)
	defer stopFn()
	if err := fetchBlobAndVerify(engA, "100.64.100.3:18080", 1, 0, blobBytes); err != nil {
		t.Fatalf("baseline direct A→B transfer failed: %v", err)
	}

	// Capture proxyDirectAB stats before flipping; we want to see
	// non-zero forwarded BEFORE the flip and non-zero dropped AFTER.
	fwdBefore, _, _ := proxyDirectAB.Stats()

	// FLIP: 100% drop on the direct path. WG keepalive/rekey on
	// the direct session can no longer succeed. Hub-bound NAT
	// proxies remain clean — relay path stays available.
	proxyDirectAB.SetPolicy(chaosPolicy{LossRate: 1.0})

	// Wait for the engine to detect the dead direct path.
	// refreshDynamicPeerActivity runs at the end of each 15s
	// mesh-poll cycle. With ActivePeerWindowSeconds=120 (default,
	// matched to wireguard-go's rekey cadence), worst-case
	// detection: 120s (between-rekey edge) + 120s (window) +
	// 15s (poll cadence) = 255s. Set a generous 280s budget.
	const failoverBudget = 280 * time.Second
	deadline := time.Now().Add(failoverBudget)
	var aFailedOver, bFailedOver bool
	for time.Now().Before(deadline) {
		if !aFailedOver && !dynamicPeerActive(t, engA, keyB.PublicKey().String()) {
			aFailedOver = true
			t.Logf("engA observed dp.Active=false for B after %v", time.Since(deadline.Add(-failoverBudget)))
		}
		if !bFailedOver && !dynamicPeerActive(t, engB, keyA.PublicKey().String()) {
			bFailedOver = true
			t.Logf("engB observed dp.Active=false for A after %v", time.Since(deadline.Add(-failoverBudget)))
		}
		if aFailedOver && bFailedOver {
			break
		}
		// Push the polling forward — the engine's loop is on a
		// 15s ticker; we manually invoke it to keep the test
		// responsive without the test hard-spinning.
		time.Sleep(2 * time.Second)
		engA.runMeshPolling()
		engB.runMeshPolling()
	}
	if !aFailedOver {
		t.Fatalf("engA never flipped dp.Active=false for B within %v under 100%% direct-path drop", failoverBudget)
	}
	if !bFailedOver {
		t.Fatalf("engB never flipped dp.Active=false for A within %v under 100%% direct-path drop", failoverBudget)
	}

	fwdAfter, dropAfter, _ := proxyDirectAB.Stats()
	if dropAfter == 0 {
		t.Errorf("expected proxyDirectAB to drop packets after flip; got drop=0")
	}
	if fwdAfter > fwdBefore {
		// Some packets may have been mid-flight when we flipped
		// the policy; tolerate a tiny delta but warn loudly if it
		// kept forwarding (would mean the policy flip didn't take).
		// More than 5 forwards post-flip is suspicious.
		if fwdAfter-fwdBefore > 5 {
			t.Errorf("proxyDirectAB still forwarded %d packets after 100%% drop policy was set", fwdAfter-fwdBefore)
		}
	}

	// Failover happened. Now verify A↔B traffic STILL works,
	// routed via the relay (hub) instead.
	if err := fetchBlobAndVerify(engA, "100.64.100.3:18080", 1, 0, blobBytes); err != nil {
		t.Fatalf("relay-failover transfer A→B failed after dp.Active flip: %v", err)
	}

	t.Logf("relay failover: direct path 100%% dropped %d packets, dp.Active flipped false on both sides, A→B 1 MiB still byte-exact via relay",
		dropAfter)
}

// forceMeshDynamicEndpoint overrides the discovered dynamic peer's
// WG endpoint and pushes the new endpoint into wireguard-go via
// IpcSet. Test-only: production code only mutates dp.Peer.Endpoint
// through addMeshDiscoveredPeers.
func forceMeshDynamicEndpoint(eng *Engine, publicKey, endpoint string) error {
	eng.dynamicMu.Lock()
	dp := eng.dynamicPeers[publicKey]
	if dp == nil {
		eng.dynamicMu.Unlock()
		return fmt.Errorf("dynamic peer %s not found", publicKey)
	}
	dp.Peer.Endpoint = endpoint
	peer := dp.Peer
	eng.dynamicMu.Unlock()
	if err := eng.upsertDynamicPeerDevice(peer); err != nil {
		return err
	}
	return eng.reconcileDynamicPeerPriority()
}

// dynamicPeerActive reads dp.Active for the named dynamic peer.
// Returns false if the peer is not present (which is also a form
// of "no longer active" from the relay-failover perspective).
func dynamicPeerActive(t *testing.T, eng *Engine, publicKey string) bool {
	t.Helper()
	eng.dynamicMu.Lock()
	defer eng.dynamicMu.Unlock()
	dp, ok := eng.dynamicPeers[publicKey]
	if !ok || dp == nil {
		return false
	}
	return dp.Active
}

// waitDynamicPeerHandshake polls until the dynamic peer with the
// given public key has completed a WG handshake (HasHandshake +
// recent), or the timeout fires.
func waitDynamicPeerHandshake(t *testing.T, eng *Engine, publicKey string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := eng.Status()
		if err != nil {
			t.Fatalf("Status: %v", err)
		}
		for _, p := range st.Peers {
			if p.PublicKey == publicKey && p.Dynamic && p.HasHandshake {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("dynamic peer %s never completed WG handshake within %v", publicKey, timeout)
}
