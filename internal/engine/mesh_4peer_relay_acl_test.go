// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite

package engine

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestMesh4PeerDynamicACLAndFallback covers the multi-phase scenario in
// docs/internal/release-checklist.md (the "mean" mesh test): four
// peers, dynamic ACL distribution, source-port spoofing, malicious
// participant, and trusted-peer bypass. See the per-subtest comments
// for what each phase pins.
//
// Topology
//
//	Peer A (100.64.98.1)  — hub. Mesh control listener. Static relay
//	                         ACL set per phase. NOT a participant
//	                         beyond serving mesh + relaying packets.
//	Peer B (100.64.98.2)  — mesh DISABLED. Just a non-participant
//	                         tunnel peer that runs an HTTP echo
//	                         server. Used to verify that traffic to
//	                         a non-participant is rejected
//	                         regardless of any mesh state.
//	Peer C (100.64.98.3)  — mesh participant. Runs an HTTP echo
//	                         server, also acts as the "attacker" in
//	                         later subtests.
//	Peer D (100.64.98.4)  — mesh participant. Runs an HTTP echo
//	                         server, also the destination in spoof
//	                         attempts.
//
// Each subtest is independent of the next: state established in an
// earlier phase (static ACLs, mesh polling, dynamic-peer activation)
// is set up once at the top of the outer test and re-used. A subtest
// failure does not leak state into later subtests beyond what's
// documented in its body.
//
// Gated behind UWGS_STRESS=1: this brings up four engines, runs mesh
// polling, and exchanges several TCP flows. ~10-30s under happy-path
// timing, much longer when something is broken. Doesn't belong on
// every PR push; release.yml flips the flag on.
func TestMesh4PeerDynamicACLAndFallback(t *testing.T) {
	if os.Getenv("UWGS_STRESS") == "" {
		t.Skip("set UWGS_STRESS=1 to run the multi-peer mesh stress test")
	}

	keys := struct {
		A, B, C, D wgtypes.Key
	}{
		A: mustMeshKey(t),
		B: mustMeshKey(t),
		C: mustMeshKey(t),
		D: mustMeshKey(t),
	}
	pskAB := mustMeshKey(t).String()
	pskAC := mustMeshKey(t).String()
	pskAD := mustMeshKey(t).String()
	serverPort := freeUDPPortTest(t)

	// --- Peer A: hub + relay + mesh listener ---
	cfgA := config.Default()
	cfgA.MeshControl.Listen = "100.64.98.1:8787"
	cfgA.WireGuard.PrivateKey = keys.A.String()
	cfgA.WireGuard.ListenPort = &serverPort
	cfgA.WireGuard.Addresses = []string{"100.64.98.1/32"}
	relayOn := true
	cfgA.Relay.Enabled = &relayOn
	cfgA.ACL.RelayDefault = acl.Deny
	// Phase 1 (static-ACL only): allow ONLY D->C:80. Everything else
	// is denied at the relay. Later phases mutate this via Engine
	// helpers below.
	cfgA.ACL.Relay = []acl.Rule{{
		Action:      acl.Allow,
		Source:      "100.64.98.4/32",
		Destination: "100.64.98.3/32",
		DestPort:    "80",
		Protocol:    "tcp",
	}}
	cfgA.WireGuard.Peers = []config.Peer{
		// B: not a mesh participant — bare tunnel peer.
		{PublicKey: keys.B.PublicKey().String(), PresharedKey: pskAB, AllowedIPs: []string{"100.64.98.2/32"}},
		// C, D: A's view of them is "mesh participant, ACL-capable".
		// This is what the relay-fallback gate consults — it is the
		// SERVER's belief about each side's capability, independent
		// of whether the peer actually enforces.
		{PublicKey: keys.C.PublicKey().String(), PresharedKey: pskAC, AllowedIPs: []string{"100.64.98.3/32"}, MeshEnabled: true, MeshAcceptACLs: true},
		{PublicKey: keys.D.PublicKey().String(), PresharedKey: pskAD, AllowedIPs: []string{"100.64.98.4/32"}, MeshEnabled: true, MeshAcceptACLs: true},
	}
	server := mustStartMeshEngine(t, cfgA)
	defer server.Close()

	// --- Generic client config builder for B/C/D ---
	clientPeerCfg := func(privKey wgtypes.Key, addr string, peers []config.Peer) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = privKey.String()
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = peers
		return cfg
	}

	// AllowedIPs are listed as explicit /32 per peer rather than the
	// covering /24. Reason: after mesh polling, the engine inserts
	// dynamic-peer entries in the WG device with /32 AllowedIPs for the
	// learned peers. If the static-A-peer entry uses /24, the new /32
	// dynamic entries are MORE specific and WG starts routing matching
	// flows to the dynamic peer — which has no working transport in a
	// netstack-only test, so packets are dropped. Listing each /32
	// explicitly on the static A-peer entry leaves the routing
	// unambiguous on the equal-prefix tie.
	allClients := "100.64.98.1/32,100.64.98.2/32,100.64.98.3/32,100.64.98.4/32"
	asAllowedList := func(s string) []string {
		out := []string{}
		for _, p := range bytesSplit(s, ',') {
			out = append(out, p)
		}
		return out
	}

	// --- Peer B: non-participant. ---
	cfgB := clientPeerCfg(keys.B, "100.64.98.2/32", []config.Peer{{
		PublicKey:           keys.A.PublicKey().String(),
		PresharedKey:        pskAB,
		Endpoint:            "127.0.0.1:" + strconv.Itoa(serverPort),
		AllowedIPs:          asAllowedList(allClients),
		PersistentKeepalive: 1,
	}})
	clientB := mustStartMeshEngine(t, cfgB)
	defer clientB.Close()

	// --- Peer C: mesh participant. ---
	cfgC := clientPeerCfg(keys.C, "100.64.98.3/32", []config.Peer{{
		PublicKey:           keys.A.PublicKey().String(),
		PresharedKey:        pskAC,
		Endpoint:            "127.0.0.1:" + strconv.Itoa(serverPort),
		AllowedIPs:          asAllowedList(allClients),
		PersistentKeepalive: 1,
		ControlURL:          "http://100.64.98.1:8787",
		MeshEnabled:         true,
		MeshAcceptACLs:      true,
	}})
	clientC := mustStartMeshEngine(t, cfgC)
	defer clientC.Close()

	// --- Peer D: mesh participant. ---
	cfgD := clientPeerCfg(keys.D, "100.64.98.4/32", []config.Peer{{
		PublicKey:           keys.A.PublicKey().String(),
		PresharedKey:        pskAD,
		Endpoint:            "127.0.0.1:" + strconv.Itoa(serverPort),
		AllowedIPs:          asAllowedList(allClients),
		PersistentKeepalive: 1,
		ControlURL:          "http://100.64.98.1:8787",
		MeshEnabled:         true,
		MeshAcceptACLs:      true,
	}})
	clientD := mustStartMeshEngine(t, cfgD)
	defer clientD.Close()

	for _, w := range []struct {
		eng *Engine
		key string
	}{
		{server, keys.B.PublicKey().String()},
		{server, keys.C.PublicKey().String()},
		{server, keys.D.PublicKey().String()},
		{clientB, keys.A.PublicKey().String()},
		{clientC, keys.A.PublicKey().String()},
		{clientD, keys.A.PublicKey().String()},
	} {
		waitPeerHandshakeTest(t, w.eng, w.key)
	}

	// --- HTTP echo servers on B, C, D (port 80 each) ---
	stopB := startTunnelHTTPEcho(t, clientB, "100.64.98.2:80", "hello world, peer B")
	defer stopB()
	echoCBody := "Hello World, peer C"
	stopC := startTunnelHTTPEcho(t, clientC, "100.64.98.3:80", echoCBody)
	defer stopC()
	stopD := startTunnelHTTPEcho(t, clientD, "100.64.98.4:80", "hello world, peer D")
	defer stopD()

	// =========================================================
	// Phase 1: static relay ACLs only. No mesh state yet.
	// Server allows ONLY D->C:80. Everything else MUST be denied
	// at the relay layer.
	// =========================================================
	t.Run("phase1_static_acls_no_mesh", func(t *testing.T) {
		// D->C should succeed (matches the explicit allow rule).
		mustHTTPGetThroughTunnel(t, clientD, "100.64.98.3:80", echoCBody)
		// C->D, B->D, B->C, C->B, D->B all denied.
		for _, dial := range []struct {
			from *Engine
			fromName string
			target   string
		}{
			{clientC, "C", "100.64.98.4:80"},
			{clientB, "B", "100.64.98.4:80"},
			{clientB, "B", "100.64.98.3:80"},
			{clientC, "C", "100.64.98.2:80"},
			{clientD, "D", "100.64.98.2:80"},
		} {
			if reachable := tryHTTPGet(dial.from, dial.target, 800*time.Millisecond); reachable {
				t.Errorf("phase1: %s->%s succeeded but relay ACL should have denied", dial.fromName, dial.target)
			}
		}
	})

	// =========================================================
	// Phase 2: mesh polling. C and D learn each other from A,
	// dynamic ACLs sync, the explicit relay allow on D->C
	// remains the only relay-acl rule. With both peers ACL-
	// capable, the relay's stateless-fallback gate kicks in:
	// the relay daemon now passes-through traffic that the
	// existing static rules would reject, trusting C and D to
	// enforce client-side. So D->C still works, AND the
	// previously-denied C->D should reach D's listener — but
	// then be filtered by D's INBOUND mesh ACL because the
	// distributed default-deny says only D->C:80 is allowed.
	// =========================================================
	clientC.runMeshPolling()
	clientD.runMeshPolling()
	waitDynamicPeerStatus(t, clientC, keys.D.PublicKey().String())
	waitDynamicPeerStatus(t, clientD, keys.C.PublicKey().String())
	forceMeshDynamicActive(t, clientC, keys.D.PublicKey().String())
	forceMeshDynamicActive(t, clientD, keys.C.PublicKey().String())

	t.Run("phase2_dynamic_acls_distributed", func(t *testing.T) {
		// D->C still works (the only allowed flow at A).
		mustHTTPGetThroughTunnel(t, clientD, "100.64.98.3:80", echoCBody)
		// C->D: A relays it (fallback, both capable), but D's
		// dynamic ACL should still deny inbound — the projected
		// rules from A say "D may receive from D, dest C:80",
		// not "D may receive from C". So this still fails.
		if reachable := tryHTTPGet(clientC, "100.64.98.4:80", 800*time.Millisecond); reachable {
			t.Errorf("phase2: C->D succeeded but D's inbound dynamic ACL should deny")
		}
		// B->C / B->D: B isn't a mesh participant. The relay's
		// fallback gate requires BOTH peers be ACL-capable; B is
		// not. So the relay denies these.
		if reachable := tryHTTPGet(clientB, "100.64.98.3:80", 800*time.Millisecond); reachable {
			t.Errorf("phase2: B->C succeeded but B is not mesh-capable; relay should deny")
		}
		if reachable := tryHTTPGet(clientB, "100.64.98.4:80", 800*time.Millisecond); reachable {
			t.Errorf("phase2: B->D succeeded but B is not mesh-capable; relay should deny")
		}
	})

	// =========================================================
	// Phase 3: source-port-80 spoofing from C, with C
	// LEGITIMATELY enforcing dynamic ACLs.
	//
	// C binds an outbound TCP socket on source port 80 and
	// dials D:80, so the 5-tuple looks like the reverse of a
	// "D connects to C:80" — which IS in the allow list. The
	// relay sees no conntrack entry for this flow, falls back
	// to the stateless gate (both ACL-capable, so allowed), and
	// passes the SYN through. C is supposed to reject this on
	// its OUTBOUND side because C's projected ACLs from A say
	// "as the destination C, accept from D:80" — saying
	// nothing about C originating to D:80.
	// =========================================================
	t.Run("phase3_legit_C_blocks_source_port_spoof_outbound", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		conn, err := clientC.net.DialContextTCPAddrPortWithBind(ctx,
			netip.MustParseAddrPort("100.64.98.4:80"),
			netip.MustParseAddrPort("100.64.98.3:80"))
		if err == nil {
			conn.Close()
			t.Errorf("phase3: source-port-80 spoof from C->D unexpectedly succeeded; outbound ACL should reject on C")
		}
	})

	// =========================================================
	// Phase 4: malicious C disables LOCAL ACL enforcement but
	// still advertises itself to A as ACL-capable.
	//
	// Implementation: C's config has MeshAcceptACLs=true (so A's
	// view of C's capability stays the same) but we sabotage C's
	// local enforcement by zeroing the meshACL maps. This is the
	// test-only equivalent of an attacker who patches their own
	// preload to skip the enforcement check. The server still
	// thinks C is capable; C silently drops the rules.
	//
	// Now the same source-port-80 spoof from C reaches the wire.
	// It goes through A's relay (fallback both-capable) and lands
	// at D. D's dynamic ACL on the INBOUND side is still active
	// and rejects it — that's the load-bearing assertion.
	// =========================================================
	t.Run("phase4_malicious_C_inbound_ACL_on_D_protects", func(t *testing.T) {
		// Snapshot then sabotage C's local enforcement.
		restoreC := sabotageLocalMeshACLs(t, clientC)
		defer restoreC()

		// Spoof from C with source port 80. Without C's outbound
		// gate to stop us at egress, the SYN now traverses C ->
		// A (relay) -> D. The connection should still fail
		// because D enforces inbound dynamic ACLs.
		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		conn, err := clientC.net.DialContextTCPAddrPortWithBind(ctx,
			netip.MustParseAddrPort("100.64.98.4:80"),
			netip.MustParseAddrPort("100.64.98.3:80"))
		if err == nil {
			conn.Close()
			t.Errorf("phase4: malicious-C source-port spoof reached D; D's inbound ACL must reject")
		}

		// Variant: C tries an arbitrary (non-spoofed) source port
		// to D:80. Same outcome expected; the server-side
		// fallback may pass through, but D's inbound ACL says
		// "from D dest C:80", not "from C dest D:80".
		ctx2, cancel2 := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel2()
		conn2, err := clientC.net.DialContextTCPAddrPortWithBind(ctx2,
			netip.MustParseAddrPort("100.64.98.4:80"),
			netip.MustParseAddrPort("100.64.98.3:23456"))
		if err == nil {
			conn2.Close()
			t.Errorf("phase4: malicious-C arbitrary-source-port to D reached destination; D's inbound ACL must reject")
		}
	})

	// =========================================================
	// Phase 5: even with malicious C, a connection to B (a
	// non-mesh-participant) MUST fail server-side. The relay's
	// fallback requires BOTH peers to be ACL-capable, and B is
	// not. So no traffic from C ever reaches B regardless of
	// source port games or whether C enforces locally.
	// =========================================================
	t.Run("phase5_malicious_C_to_non_mesh_B_blocked_at_relay", func(t *testing.T) {
		restoreC := sabotageLocalMeshACLs(t, clientC)
		defer restoreC()

		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		conn, err := clientC.net.DialContextTCPAddrPortWithBind(ctx,
			netip.MustParseAddrPort("100.64.98.2:80"),
			netip.MustParseAddrPort("100.64.98.3:80"))
		if err == nil {
			conn.Close()
			t.Errorf("phase5: C->B-with-source-port-80 reached B; relay should reject (B not mesh-capable)")
		}
	})

	// =========================================================
	// Phase 6: server marks C as MeshTrustTrustedAlways. This
	// is documented as "skip the both-capable requirement on
	// the relay's stateless-fallback gate", NOT "bypass static
	// ACLs entirely". So C->B:80 with source-port spoofing
	// STILL fails because there is no static rule covering
	// C↔B in either direction. This subtest exists to pin that
	// distinction — TrustedAlways doesn't suddenly turn the
	// relay into open-by-default.
	// =========================================================
	t.Run("phase6_trusted_always_does_not_bypass_static_ACL", func(t *testing.T) {
		setPeerMeshTrust(t, server, keys.C.PublicKey().String(),
			config.MeshTrustTrustedAlways)
		defer setPeerMeshTrust(t, server, keys.C.PublicKey().String(),
			config.MeshTrustUntrusted)

		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		conn, err := clientC.net.DialContextTCPAddrPortWithBind(ctx,
			netip.MustParseAddrPort("100.64.98.2:80"),
			netip.MustParseAddrPort("100.64.98.3:80"))
		if err == nil {
			conn.Close()
			t.Errorf("phase6: trusted-always C->B succeeded; relay should deny because no static rule covers C↔B in either direction")
		}
	})

	// =========================================================
	// Phase 7: trusted-always-C → D:80 with source port 80,
	// D enforcing dynamic ACLs.
	//
	// This time the server-side fallback DOES allow:
	//  - meshRelayACLFallbackAllowed says "C is TrustedAlways → ok"
	//  - relayAllowed in the REVERSE direction matches the
	//    "D→C:80" rule (because the swap makes the forward
	//    look like D→C with destPort=80). So fallback returns
	//    true and the SYN reaches D.
	// D's inbound dynamic-ACL projection from A says "as the
	// destination, accept from D src dest C:80" — saying
	// nothing about being the destination of C-originated
	// traffic. So D rejects on inbound, even though the server
	// passed it through. This is the "server passes, client
	// validates" property the maintainer asked us to pin.
	// =========================================================
	t.Run("phase7_trusted_always_C_blocked_by_D_inbound_ACL", func(t *testing.T) {
		setPeerMeshTrust(t, server, keys.C.PublicKey().String(),
			config.MeshTrustTrustedAlways)
		defer setPeerMeshTrust(t, server, keys.C.PublicKey().String(),
			config.MeshTrustUntrusted)

		ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
		defer cancel()
		conn, err := clientC.net.DialContextTCPAddrPortWithBind(ctx,
			netip.MustParseAddrPort("100.64.98.4:80"),
			netip.MustParseAddrPort("100.64.98.3:80"))
		if err == nil {
			conn.Close()
			t.Errorf("phase7: trusted-always C->D with D enforcing dynamic ACL succeeded; D's inbound ACL must reject")
		}
	})
}

// --- helpers (test-local) -----------------------------------------------

// startTunnelHTTPEcho starts a tiny HTTP listener inside the engine's
// netstack on the given tunnel address that responds with `body` to any
// request and returns a cleanup function.
func startTunnelHTTPEcho(t *testing.T, eng *Engine, addrPort string, body string) func() {
	t.Helper()
	ap := netip.MustParseAddrPort(addrPort)
	ln, err := eng.ListenTCP(ap)
	if err != nil {
		t.Fatalf("listen %s on %s: %v", addrPort, eng.cfg.WireGuard.Addresses, err)
	}
	stopped := atomic.Bool{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(2 * time.Second))
				buf := make([]byte, 1024)
				_, _ = c.Read(buf)
				resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
				_, _ = io.WriteString(c, resp)
			}(c)
		}
	}()
	return func() {
		stopped.Store(true)
		_ = ln.Close()
	}
}

// tryHTTPGet attempts a single HTTP GET through the engine's tunnel
// dialer with the given timeout. Returns true if the response body
// could be read (any bytes), false if the connection failed or timed
// out — used for the "should be denied" assertions where we don't care
// about the body content, only whether the flow established.
func tryHTTPGet(eng *Engine, addrPort string, timeout time.Duration) bool {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	conn, err := eng.net.DialContextTCPAddrPort(ctx, netip.MustParseAddrPort(addrPort))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		return false
	}
	buf := make([]byte, 16)
	n, _ := conn.Read(buf)
	return n > 0
}

// mustHTTPGetThroughTunnel is the positive-assertion variant: dials,
// reads the response, fails the test if the body doesn't contain the
// expected substring.
func mustHTTPGetThroughTunnel(t *testing.T, eng *Engine, addrPort, wantBody string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := retryMeshDialContextWithContext(ctx, eng, "tcp", addrPort, 30*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addrPort, err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(conn, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"); err != nil {
		t.Fatalf("write request: %v", err)
	}
	body, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	if !bytes.Contains(body, []byte(wantBody)) {
		t.Fatalf("response body %q does not contain %q", body, wantBody)
	}
}

func netipMustAddr(s string) netip.Addr {
	a, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return a
}

// bytesSplit is a tiny dependency-free split-by-rune. Avoids strings.Split
// because the test file is already heavy on imports; keeping it local
// makes the AllowedIPs builder above readable without adding noise.
func bytesSplit(s string, sep rune) []string {
	out := []string{}
	start := 0
	for i, r := range s {
		if r == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// sabotageLocalMeshACLs simulates the malicious-C scenario: the peer
// claims to be ACL-capable to the mesh server (its config still has
// MeshAcceptACLs=true and the server's view is unchanged) but locally
// it ignores any distributed ACL by clearing its mesh ACL maps. The
// returned restore function reinstates the original ACL state so
// subsequent subtests are not affected.
func sabotageLocalMeshACLs(t *testing.T, eng *Engine) func() {
	t.Helper()
	eng.meshACLMu.Lock()
	savedIn := eng.meshACLsIn
	savedOut := eng.meshACLsOut
	eng.meshACLsIn = make(map[string]acl.List)
	eng.meshACLsOut = make(map[string]acl.List)
	eng.meshACLMu.Unlock()
	return func() {
		eng.meshACLMu.Lock()
		eng.meshACLsIn = savedIn
		eng.meshACLsOut = savedOut
		eng.meshACLMu.Unlock()
	}
}

// setPeerMeshTrust mutates a peer's MeshTrust value on a running
// engine. We do this by direct config manipulation under cfgMu rather
// than going through the runtime API — the API path requires the
// config to round-trip through Normalize and a public schema, which
// would also mutate sibling fields we want to leave alone.
func setPeerMeshTrust(t *testing.T, eng *Engine, publicKey string, trust config.MeshTrust) {
	t.Helper()
	eng.cfgMu.Lock()
	defer eng.cfgMu.Unlock()
	for i := range eng.cfg.WireGuard.Peers {
		if eng.cfg.WireGuard.Peers[i].PublicKey == publicKey {
			eng.cfg.WireGuard.Peers[i].MeshTrust = trust
			return
		}
	}
	t.Fatalf("peer %s not found in engine config", publicKey)
}
