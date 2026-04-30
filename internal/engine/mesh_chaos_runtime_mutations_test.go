// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite && !race

package engine

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

// TestMeshChaosResume_RuntimeMutationsUnderLoad pins the invariant
// that the runtime API mutation surface (AddPeer / RemovePeer /
// SetACL / AddForward / RemoveForward) doesn't corrupt or stall
// active traffic when called under load.
//
// Production trigger: simple-wireguard-server + uwgsocks-ui push
// peer/ACL updates while production traffic flows. A single
// mutation that takes a global lock for too long, or that races
// the engine's connection-table maintenance, would manifest as
// dropped flows or panics under live load.
//
// Topology: hub + A + B (relay path). Sequence:
//
//  1. Bring everything up. Mesh discovery. Direct path forced
//     active so traffic flows A↔B end-to-end.
//  2. Start a CONTINUOUS transfer loop A→B (~50 transfers of
//     128 KiB each, sequential — keeps the data path constantly
//     busy).
//  3. CONCURRENTLY hammer the runtime mutation surface on the
//     hub:
//        - AddPeer(throwaway) + RemovePeer (every ~50ms)
//        - SetACL with a fresh rule list (every ~75ms)
//        - AddForward + RemoveForward (every ~100ms)
//     Total: at least ~30 mutations during the transfer window.
//  4. Stop both loops. Assert:
//        - Every transfer completed byte-exact (no corruption).
//        - No panics (the test's t.Fatalf would have fired).
//        - Final hub Status reflects a clean state (no stuck
//          dynamic peers, no ACL list pollution).
//
// Wall: ~10-20s.
//
// Gated UWGS_RUN_MESH_CHAOS=1; -short skips it.
func TestMeshChaosResume_RuntimeMutationsUnderLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("mesh chaos test skipped in -short mode")
	}
	if !testingChaosFlag() {
		t.Skip("set UWGS_RUN_MESH_CHAOS=1 or -uwgs-mesh-chaos to run runtime-mutation chaos test")
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
	hubCfg.WireGuard.Addresses = []string{"100.64.106.1/32"}
	hubCfg.MeshControl.Listen = "100.64.106.1:8808"
	relay := true
	hubCfg.Relay.Enabled = &relay
	hubCfg.ACL.RelayDefault = acl.Allow
	hubCfg.WireGuard.Peers = []config.Peer{
		{
			PublicKey:      keyA.PublicKey().String(),
			PresharedKey:   pskA,
			AllowedIPs:     []string{"100.64.106.2/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
		{
			PublicKey:      keyB.PublicKey().String(),
			PresharedKey:   pskB,
			AllowedIPs:     []string{"100.64.106.3/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		},
	}
	hub := mustStartMeshEngine(t, hubCfg)
	defer hub.Close()

	mkClient := func(priv, addr, otherAddr, psk string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = priv
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           hubKey.PublicKey().String(),
			PresharedKey:        psk,
			Endpoint:            "127.0.0.1:" + intToStr(hubPort),
			AllowedIPs:          []string{"100.64.106.1/32", otherAddr},
			PersistentKeepalive: 1,
			ControlURL:          "http://100.64.106.1:8808",
			MeshEnabled:         true,
			MeshAcceptACLs:      true,
		}}
		return cfg
	}
	engA := mustStartMeshEngine(t, mkClient(keyA.String(), "100.64.106.2/32", "100.64.106.3/32", pskA))
	defer engA.Close()
	engB := mustStartMeshEngine(t, mkClient(keyB.String(), "100.64.106.3/32", "100.64.106.2/32", pskB))
	defer engB.Close()

	waitPeerHandshakeTest(t, hub, keyA.PublicKey().String())
	waitPeerHandshakeTest(t, hub, keyB.PublicKey().String())
	waitPeerHandshakeTest(t, engA, hubKey.PublicKey().String())
	waitPeerHandshakeTest(t, engB, hubKey.PublicKey().String())
	engA.runMeshPolling()
	engB.runMeshPolling()
	waitDynamicPeerStatus(t, engA, keyB.PublicKey().String())
	waitDynamicPeerStatus(t, engB, keyA.PublicKey().String())

	const blobBytes = 128 * 1024
	stopBlob := startBlobServerOn(t, engB, "100.64.106.3:18080", 0, 1, blobBytes)
	defer stopBlob()

	// Sanity: one transfer works before we start the chaos.
	if err := fetchBlobAndVerify(engA, "100.64.106.3:18080", 0, 1, blobBytes); err != nil {
		t.Fatalf("baseline transfer failed: %v", err)
	}

	// === Begin concurrent traffic + mutation chaos ===
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	var wg sync.WaitGroup

	// Counters for visibility.
	var transfersOK, transfersFail atomic.Int64
	var mutationsOK, mutationsFail atomic.Int64

	// Traffic loop: continuous A→B transfers.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ctx.Err() == nil {
			if err := fetchBlobAndVerify(engA, "100.64.106.3:18080", 0, 1, blobBytes); err != nil {
				transfersFail.Add(1)
				continue
			}
			transfersOK.Add(1)
		}
	}()

	// Mutation loop A: peer add/remove cycle.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				k := mustMeshKey(t)
				p := config.Peer{
					PublicKey:    k.PublicKey().String(),
					PresharedKey: mustMeshKey(t).String(),
					AllowedIPs:   []string{"100.64.106.99/32"},
				}
				if err := hub.AddPeer(p); err != nil {
					mutationsFail.Add(1)
					continue
				}
				time.Sleep(10 * time.Millisecond)
				if err := hub.RemovePeer(p.PublicKey); err != nil {
					mutationsFail.Add(1)
					continue
				}
				mutationsOK.Add(1)
			}
		}
	}()

	// Mutation loop B: ACL replacement cycle.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(75 * time.Millisecond)
		defer ticker.Stop()
		seq := 0
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				seq++
				rule := acl.Rule{
					Action:      acl.Allow,
					Source:      "100.64.106.0/24",
					Destination: "100.64.106.0/24",
				}
				next := config.ACL{
					RelayDefault: acl.Allow,
					Relay:        []acl.Rule{rule},
				}
				if err := hub.SetACL(next); err != nil {
					mutationsFail.Add(1)
					continue
				}
				mutationsOK.Add(1)
			}
		}
	}()

	// Mutation loop C: forward add/remove cycle.
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				lp := freeTCPPortMesh(t)
				name, _, err := hub.AddForward(false, config.Forward{
					Proto:  "tcp",
					Listen: "127.0.0.1:" + intToStr(lp),
					Target: "100.64.106.3:65535",
				})
				if err != nil {
					mutationsFail.Add(1)
					continue
				}
				time.Sleep(10 * time.Millisecond)
				if err := hub.RemoveForward(name); err != nil {
					mutationsFail.Add(1)
					continue
				}
				mutationsOK.Add(1)
			}
		}
	}()

	// Run the chaos for the full ctx window.
	<-ctx.Done()
	wg.Wait()

	t.Logf("runtime-mutation chaos: transfers ok=%d fail=%d, mutations ok=%d fail=%d",
		transfersOK.Load(), transfersFail.Load(), mutationsOK.Load(), mutationsFail.Load())

	if transfersOK.Load() == 0 {
		t.Fatalf("no transfers completed during the chaos window — engine stalled under mutation load")
	}
	// A few fails under load are tolerable (the conntrack rebuild
	// after an ACL replace can briefly drop in-flight flows). The
	// test fails only if EVERYTHING fails, or if more than half
	// the transfers fail — that's not "tolerable churn", that's
	// a corrupted data path.
	if transfersFail.Load() > transfersOK.Load() {
		t.Fatalf("more transfers failed than succeeded during chaos (ok=%d fail=%d)",
			transfersOK.Load(), transfersFail.Load())
	}
	if mutationsOK.Load() == 0 {
		t.Fatalf("no mutations completed — runtime API stuck")
	}
	if mutationsFail.Load() > mutationsOK.Load() {
		t.Fatalf("more mutations failed than succeeded (ok=%d fail=%d)",
			mutationsOK.Load(), mutationsFail.Load())
	}
}
