// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite && !race

package engine

import (
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

// TestMeshChaosResume_HubProcessRestart pins the production code
// path that fires when the hub uwgsocks process crashes and is
// restarted by a supervisor. This is the single most common
// operations event for a deployed hub: kernel OOM kills the
// process, a config push triggers a graceful restart, a runtime
// upgrade rotates the binary. In all of these cases:
//
//   1. The hub's mesh-control HTTP listener disappears.
//   2. Client engines lose their WG handshake to the hub.
//   3. Any in-flight relay flow loses its conntrack entry.
//   4. The hub comes back with the same config + the same WG key.
//   5. Clients MUST re-handshake automatically (PersistentKeepalive
//      drives this; we assert on it).
//   6. Mesh-control polling MUST resume; clients re-discover
//      each other.
//   7. New relay flows must establish + complete byte-exact.
//
// The previous in-flight flows are NOT expected to resume — TCP
// retransmits at the application layer would have to bring those
// back, which is application-specific. What we DO assert is that
// new flows after the restart work, which is the real production
// invariant.
//
// Wall: ~5-15s (one handshake + one transfer + restart + another
// handshake + another transfer).
//
// Gated by UWGS_RUN_MESH_CHAOS=1; -short skips it.
func TestMeshChaosResume_HubProcessRestart(t *testing.T) {
	if testing.Short() {
		t.Skip("mesh chaos test skipped in -short mode")
	}
	if !testingChaosFlag() {
		t.Skip("set UWGS_RUN_MESH_CHAOS=1 or -uwgs-mesh-chaos to run hub-restart chaos test")
	}

	hubKey := mustMeshKey(t)
	keyA := mustMeshKey(t)
	keyB := mustMeshKey(t)
	hubPort := freeUDPPortTest(t)

	pskA := mustMeshKey(t).String()
	pskB := mustMeshKey(t).String()

	// Build hub config — captured in a builder so we can construct
	// a fresh Engine with the SAME settings post-restart. The same
	// hubPort is reused: the port allocator returns ports the OS
	// considers free; closing the engine releases the port; a new
	// engine binding the same port should succeed (TIME_WAIT
	// doesn't apply to UDP).
	buildHubCfg := func() config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = hubKey.String()
		cfg.WireGuard.ListenPort = &hubPort
		cfg.WireGuard.Addresses = []string{"100.64.103.1/32"}
		cfg.MeshControl.Listen = "100.64.103.1:8805"
		relay := true
		cfg.Relay.Enabled = &relay
		cfg.ACL.RelayDefault = acl.Allow
		cfg.WireGuard.Peers = []config.Peer{
			{
				PublicKey:      keyA.PublicKey().String(),
				PresharedKey:   pskA,
				AllowedIPs:     []string{"100.64.103.2/32"},
				MeshEnabled:    true,
				MeshAcceptACLs: true,
			},
			{
				PublicKey:      keyB.PublicKey().String(),
				PresharedKey:   pskB,
				AllowedIPs:     []string{"100.64.103.3/32"},
				MeshEnabled:    true,
				MeshAcceptACLs: true,
			},
		}
		return cfg
	}
	hub := mustStartMeshEngine(t, buildHubCfg())

	clientCfg := func(priv, addr, otherAddr, psk string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = priv
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           hubKey.PublicKey().String(),
			PresharedKey:        psk,
			Endpoint:            "127.0.0.1:" + intToStr(hubPort),
			AllowedIPs:          []string{"100.64.103.1/32", otherAddr},
			PersistentKeepalive: 1,
			ControlURL:          "http://100.64.103.1:8805",
			MeshEnabled:         true,
			MeshAcceptACLs:      true,
		}}
		return cfg
	}

	engA := mustStartMeshEngine(t, clientCfg(
		keyA.String(), "100.64.103.2/32", "100.64.103.3/32", pskA,
	))
	defer engA.Close()
	engB := mustStartMeshEngine(t, clientCfg(
		keyB.String(), "100.64.103.3/32", "100.64.103.2/32", pskB,
	))
	defer engB.Close()

	waitPeerHandshakeTest(t, hub, keyA.PublicKey().String())
	waitPeerHandshakeTest(t, hub, keyB.PublicKey().String())
	waitPeerHandshakeTest(t, engA, hubKey.PublicKey().String())
	waitPeerHandshakeTest(t, engB, hubKey.PublicKey().String())

	engA.runMeshPolling()
	engB.runMeshPolling()
	waitDynamicPeerStatus(t, engA, keyB.PublicKey().String())
	waitDynamicPeerStatus(t, engB, keyA.PublicKey().String())

	// Baseline relay transfer A → B works. Leave the blob server
	// up across the hub restart — engB itself isn't restarted, so
	// its tunnel-side listener stays valid; restarting it races
	// the netstack port-release timer.
	const blobBytes = 256 * 1024
	stopFn := startBlobServerOn(t, engB, "100.64.103.3:18080", 0, 1, blobBytes)
	defer stopFn()
	if err := fetchBlobAndVerify(engA, "100.64.103.3:18080", 0, 1, blobBytes); err != nil {
		t.Fatalf("baseline pre-restart A→B transfer failed: %v", err)
	}

	// === CHAOS: hub crashes ===
	// Close the hub engine. This drops the WG listener, the mesh-
	// control HTTP listener, the relay conntrack, and every active
	// session. From the clients' perspective this is identical to
	// the hub process being killed by the kernel.
	t.Log("hub crash: closing hub engine")
	if err := hub.Close(); err != nil {
		t.Fatalf("hub.Close: %v", err)
	}

	// Brief delay so the OS releases the listening port. We don't
	// busy-wait the listener — UDP doesn't have a TIME_WAIT, so
	// re-binding should be immediate, but a short pause avoids
	// racing wireguard-go's internal goroutine teardown.
	time.Sleep(200 * time.Millisecond)

	// === RESTART: bring up a new hub with the same config ===
	t.Log("hub restart: starting fresh engine with same config")
	hub2 := mustStartMeshEngine(t, buildHubCfg())
	defer hub2.Close()

	// Both clients must re-handshake. The standard 5s
	// waitPeerHandshakeTest is too short — wireguard-go's session
	// invalidation + rekey trigger can take 30s+ after a peer goes
	// silent. PersistentKeepalive=1s helps but doesn't accelerate
	// the rekey itself. Use a longer wait window. Production
	// supervisor restart latency is typically a second or two
	// followed by ≤ 1 minute of session-recovery; we permit up to
	// 90s to keep the test stable on slow CI.
	t.Log("waiting for clients to re-handshake with restarted hub (up to 90s)")
	waitPeerReHandshake(t, hub2, keyA.PublicKey().String(), 90*time.Second)
	waitPeerReHandshake(t, hub2, keyB.PublicKey().String(), 90*time.Second)
	// Note: client Status.Peers shows the WG-side handshake state.
	// After the hub restart, clients DO re-handshake, but their
	// dynamic-peer state for each other still references the old
	// (pre-restart) peer config. Repolling forces a fresh
	// /v1/peers fetch from the new hub.
	engA.runMeshPolling()
	engB.runMeshPolling()

	// === Final invariant: new flows work post-restart ===
	if err := fetchBlobAndVerify(engA, "100.64.103.3:18080", 0, 1, blobBytes); err != nil {
		t.Fatalf("post-restart A→B transfer failed: %v", err)
	}

	t.Logf("hub restart: clients re-handshook automatically, mesh-control re-converged, A→B relay traffic byte-exact")
}

// waitPeerReHandshake polls until the named peer reports a fresh
// HasHandshake AND its LastHandshakeTime is more recent than the
// moment the wait started. Without the freshness check we'd see
// the pre-restart handshake time and falsely report success.
func waitPeerReHandshake(t *testing.T, eng *Engine, publicKey string, timeout time.Duration) {
	t.Helper()
	startUnix := time.Now().Unix()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		st, err := eng.Status()
		if err != nil {
			t.Fatal(err)
		}
		for _, peer := range st.Peers {
			if peer.PublicKey != publicKey {
				continue
			}
			if peer.HasHandshake && peer.LastHandshakeTimeSec >= startUnix {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for peer %s to re-handshake within %v", publicKey, timeout)
}
