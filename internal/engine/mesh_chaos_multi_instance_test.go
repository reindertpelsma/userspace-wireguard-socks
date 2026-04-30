// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite && !race

package engine

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

// TestMeshChaosResume_MultiInstanceHost pins the invariant that two
// fully-independent uwgsocks engines can run side-by-side in one
// process without any shared-state collision. Production scenarios:
//
//   - A single host runs two uwgsocks daemons (one for the office
//     VPN, one for a home VPN), each with its own config.
//   - simple-wireguard-server hosts multiple tenants, each as a
//     separate engine in the same supervisor process.
//   - Tests inside this very repo run multi-engine topologies
//     constantly — if shared-state assumptions break, every test
//     here is suspect.
//
// What we assert:
//
//  1. Two completely separate engine pairs (hub₁ + clients) run in
//     parallel using DIFFERENT WG keys, DIFFERENT tunnel address
//     families (100.64.104.0/24 vs 100.64.105.0/24), DIFFERENT
//     UDP listen ports, DIFFERENT mesh-control listen ports, and
//     DIFFERENT SOCKS5 listeners.
//  2. Each pair completes its own WG handshakes + mesh discovery.
//  3. Concurrent baseline transfers (one in each topology) both
//     finish byte-exact, with neither's bytes leaking into the
//     other's stream.
//
// This is the test that catches package-level mutables that
// should have been per-engine — gvisor netstack pool collisions
// (already fixed in beta.59 → !race build tag), shared metric
// registries, accidental global maps, etc.
//
// Wall: ~5-10s.
//
// Gated UWGS_RUN_MESH_CHAOS=1; -short skips it.
func TestMeshChaosResume_MultiInstanceHost(t *testing.T) {
	if testing.Short() {
		t.Skip("mesh chaos test skipped in -short mode")
	}
	if !testingChaosFlag() {
		t.Skip("set UWGS_RUN_MESH_CHAOS=1 or -uwgs-mesh-chaos to run multi-instance chaos test")
	}

	type instance struct {
		name           string
		hub            *Engine
		engA, engB     *Engine
		hubKey         string
		keyA, keyB     string
		bSrvAddr       string // tunnel-side blob server addr
		blobSize       int
	}

	// Build two completely independent topologies in parallel.
	// Different subnets, ports, and private keys — nothing
	// shared.
	build := func(label, subnet, mcListen string, mcPortPlus int) *instance {
		hubKey := mustMeshKey(t)
		keyA := mustMeshKey(t)
		keyB := mustMeshKey(t)
		hubPort := freeUDPPortTest(t)
		pskA := mustMeshKey(t).String()
		pskB := mustMeshKey(t).String()

		hubCfg := config.Default()
		hubCfg.WireGuard.PrivateKey = hubKey.String()
		hubCfg.WireGuard.ListenPort = &hubPort
		hubCfg.WireGuard.Addresses = []string{subnet + "1/32"}
		hubCfg.MeshControl.Listen = mcListen
		relay := true
		hubCfg.Relay.Enabled = &relay
		hubCfg.ACL.RelayDefault = acl.Allow
		hubCfg.WireGuard.Peers = []config.Peer{
			{
				PublicKey:      keyA.PublicKey().String(),
				PresharedKey:   pskA,
				AllowedIPs:     []string{subnet + "2/32"},
				MeshEnabled:    true,
				MeshAcceptACLs: true,
			},
			{
				PublicKey:      keyB.PublicKey().String(),
				PresharedKey:   pskB,
				AllowedIPs:     []string{subnet + "3/32"},
				MeshEnabled:    true,
				MeshAcceptACLs: true,
			},
		}
		hub := mustStartMeshEngine(t, hubCfg)

		mkClient := func(priv, addr, otherAddr, psk string) config.Config {
			cfg := config.Default()
			cfg.WireGuard.PrivateKey = priv
			cfg.WireGuard.Addresses = []string{addr}
			cfg.WireGuard.Peers = []config.Peer{{
				PublicKey:           hubKey.PublicKey().String(),
				PresharedKey:        psk,
				Endpoint:            "127.0.0.1:" + intToStr(hubPort),
				AllowedIPs:          []string{subnet + "1/32", otherAddr},
				PersistentKeepalive: 1,
				ControlURL:          "http://" + mcListen,
				MeshEnabled:         true,
				MeshAcceptACLs:      true,
			}}
			return cfg
		}
		engA := mustStartMeshEngine(t, mkClient(keyA.String(), subnet+"2/32", subnet+"3/32", pskA))
		engB := mustStartMeshEngine(t, mkClient(keyB.String(), subnet+"3/32", subnet+"2/32", pskB))

		waitPeerHandshakeTest(t, hub, keyA.PublicKey().String())
		waitPeerHandshakeTest(t, hub, keyB.PublicKey().String())
		waitPeerHandshakeTest(t, engA, hubKey.PublicKey().String())
		waitPeerHandshakeTest(t, engB, hubKey.PublicKey().String())
		engA.runMeshPolling()
		engB.runMeshPolling()
		waitDynamicPeerStatus(t, engA, keyB.PublicKey().String())
		waitDynamicPeerStatus(t, engB, keyA.PublicKey().String())

		_ = mcPortPlus // (kept for symmetry; mcListen already encodes it)
		return &instance{
			name:     label,
			hub:      hub,
			engA:     engA,
			engB:     engB,
			hubKey:   hubKey.PublicKey().String(),
			keyA:     keyA.PublicKey().String(),
			keyB:     keyB.PublicKey().String(),
			bSrvAddr: subnet + "3:18080",
			blobSize: 256 * 1024,
		}
	}

	inst1 := build("alpha", "100.64.104.", "100.64.104.1:8806", 0)
	defer inst1.hub.Close()
	defer inst1.engA.Close()
	defer inst1.engB.Close()
	inst2 := build("beta", "100.64.105.", "100.64.105.1:8807", 0)
	defer inst2.hub.Close()
	defer inst2.engA.Close()
	defer inst2.engB.Close()

	// Stand up the blob servers on each instance.
	stop1 := startBlobServerOn(t, inst1.engB, inst1.bSrvAddr, 0, 1, inst1.blobSize)
	defer stop1()
	stop2 := startBlobServerOn(t, inst2.engB, inst2.bSrvAddr, 0, 1, inst2.blobSize)
	defer stop2()

	// Run both transfers concurrently. Each pair has its own
	// WG keys + tunnel addr space; if anything is leaking between
	// instances we'd see either a hang (wrong-engine routing) or
	// a sha256 mismatch (cross-engine byte contamination).
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, inst := range []*instance{inst1, inst2} {
		inst := inst
		wg.Add(1)
		go func() {
			defer wg.Done()
			done := make(chan error, 1)
			go func() {
				done <- fetchBlobAndVerify(inst.engA, inst.bSrvAddr, 0, 1, inst.blobSize)
			}()
			select {
			case err := <-done:
				results <- err
			case <-ctx.Done():
				results <- ctx.Err()
			}
		}()
	}
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatalf("multi-instance concurrent transfer failed: %v", err)
		}
	}

	t.Logf("multi-instance: alpha + beta engines ran in parallel; both A→B transfers byte-exact, no cross-instance contamination")
}
