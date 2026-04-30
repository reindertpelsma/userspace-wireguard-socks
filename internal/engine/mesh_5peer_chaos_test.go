// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite && !race

package engine

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// TestMeshChaosResume_LossyDirectPath is the first chaos test
// that uses the UDP middleman (chaosProxy) to inject realistic
// packet loss + jitter between two peers' direct WG path.
//
// Topology: 2 peers (no hub — keep it tight). Peer A's WG
// endpoint for B routes through a proxy. Initially the proxy
// passes everything through cleanly; the WG handshake completes
// and a 4 MiB blob transfer starts. Mid-flight, proxy policy
// flips to LossRate=10% with up to 50ms jitter. The inner TCP
// stream's retransmit/SACK should absorb the loss and the
// transfer must complete byte-exact.
//
// What this test DOES exercise:
//   - The chaosProxy mechanics (forward, drop, delay).
//   - Inner TCP retransmit through a lossy outer transport.
//   - That a 10%-loss WG path still gets meaningful goodput.
//
// What this test does NOT exercise (deferred to a follow-up
// commit pending engine-failover code path investigation):
//   - 100%-drop on the direct path triggering keepalive/rekey
//     timeout and automatic fallback to relay through a hub.
//     The engine's auto-failover-to-relay logic (when does
//     `dp.Active` flip false on its own?) needs to be mapped
//     before that test can be written faithfully.
//   - Source-port randomization on reconnect.
//   - TCP outer transport variant.
//
// Gated by UWGS_RUN_MESH_CHAOS=1.
func TestMeshChaosResume_LossyDirectPath(t *testing.T) {
	if testing.Short() {
		t.Skip("mesh chaos test skipped in -short mode")
	}
	if !testingChaosFlag() {
		t.Skip("set UWGS_RUN_MESH_CHAOS=1 to run lossy-direct-path chaos test")
	}

	// Two-peer setup: peer A talks to peer B through the chaos
	// proxy. Both peers know each other statically; no hub.
	keyA, keyB := mustMeshKey(t), mustMeshKey(t)
	portA, portB := freeUDPPortTest(t), freeUDPPortTest(t)

	// Symmetric proxies: A→B traffic goes via proxyAB, B→A
	// traffic goes via proxyBA. Without both, WireGuard's roaming-
	// endpoint behaviour means once B replies direct to A, A
	// "learns" B's real address from the inbound packet's source
	// and bypasses the proxy. Symmetry keeps every WG datagram
	// flowing through a proxy in BOTH directions.
	proxyAB, err := startChaosProxy(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portB},
		chaosPolicy{}, // start clean
	)
	if err != nil {
		t.Fatalf("start proxy A→B: %v", err)
	}
	defer proxyAB.Close()
	proxyBA, err := startChaosProxy(
		&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: portA},
		chaosPolicy{},
	)
	if err != nil {
		t.Fatalf("start proxy B→A: %v", err)
	}
	defer proxyBA.Close()

	cfgA := config.Default()
	cfgA.WireGuard.PrivateKey = keyA.String()
	cfgA.WireGuard.ListenPort = &portA
	cfgA.WireGuard.Addresses = []string{"100.64.98.1/32"}
	cfgA.WireGuard.Peers = []config.Peer{{
		PublicKey:           keyB.PublicKey().String(),
		Endpoint:            proxyAB.Addr().String(),
		AllowedIPs:          []string{"100.64.98.2/32"},
		PersistentKeepalive: 1,
	}}
	engA := mustStartMeshEngine(t, cfgA)
	defer engA.Close()

	cfgB := config.Default()
	cfgB.WireGuard.PrivateKey = keyB.String()
	cfgB.WireGuard.ListenPort = &portB
	cfgB.WireGuard.Addresses = []string{"100.64.98.2/32"}
	cfgB.WireGuard.Peers = []config.Peer{{
		PublicKey:           keyA.PublicKey().String(),
		Endpoint:            proxyBA.Addr().String(), // through the B→A proxy
		AllowedIPs:          []string{"100.64.98.1/32"},
		PersistentKeepalive: 1,
	}}
	engB := mustStartMeshEngine(t, cfgB)
	defer engB.Close()

	// Wait for handshake.
	waitPeerHandshakeTest(t, engA, keyB.PublicKey().String())
	waitPeerHandshakeTest(t, engB, keyA.PublicKey().String())

	// Sanity: proxy is forwarding bytes both ways.
	if fw, _, _ := proxyAB.Stats(); fw == 0 {
		t.Fatalf("proxy didn't forward any handshake packets — peers can't have completed handshake")
	}

	// Stand up an HTTP blob server on B.
	blobBytes := 4 * 1024 * 1024 // 4 MiB
	stopFn := startBlobServerOn(t, engB, "100.64.98.2:18080", 0 /*srcIdx*/, 1 /*dstIdx*/, blobBytes)
	defer stopFn()

	// First transfer with clean proxy — confirm baseline works.
	if err := fetchBlobAndVerify(engA, "100.64.98.2:18080", 1, 0, blobBytes); err != nil {
		t.Fatalf("baseline (clean proxy) transfer failed: %v", err)
	}

	// Now flip BOTH proxies to lossy mode. 5% loss + 20ms jitter
	// each direction. Combined per-round-trip drop probability is
	// 1 - 0.95² ≈ 9.75%, which gVisor's TCP can absorb without
	// goodput collapse. Higher rates (10%+ each direction) drive
	// TCP retransmit-storm into pathological territory and the
	// test grinds to a halt.
	pol := chaosPolicy{
		LossRate: 0.05,
		Jitter:   20 * time.Millisecond,
	}
	proxyAB.SetPolicy(pol)
	proxyBA.SetPolicy(pol)

	// Run 5 transfers under lossy chaos. Measure goodput.
	start := time.Now()
	for i := 0; i < 5; i++ {
		if err := fetchBlobAndVerify(engA, "100.64.98.2:18080", 1, 0, blobBytes); err != nil {
			t.Fatalf("lossy transfer %d failed: %v", i, err)
		}
	}
	elapsed := time.Since(start)

	fwAB, dropAB, delayAB := proxyAB.Stats()
	fwBA, dropBA, delayBA := proxyBA.Stats()
	totalFw := fwAB + fwBA
	totalDrop := dropAB + dropBA
	throughput := float64(5*blobBytes) / elapsed.Seconds() / (1 << 20) // MiB/s
	t.Logf("lossy direct path: 5 × 4 MiB = 20 MiB through symmetric 5%%-loss + 20ms-jitter proxies in %v (%.1f MiB/s); A→B forwarded=%d dropped=%d delayed=%d; B→A forwarded=%d dropped=%d delayed=%d; combined drop ratio=%.2f%%",
		elapsed, throughput,
		fwAB, dropAB, delayAB,
		fwBA, dropBA, delayBA,
		100*float64(totalDrop)/float64(totalFw+totalDrop))
	if totalDrop == 0 {
		t.Errorf("expected the 10%% loss policy to drop SOME packets; got drop=0 (test isn't exercising loss)")
	}
}

// startBlobServerOn spawns a tunnel-side HTTP blob server on the
// given engine + address. The blob is keyed by (srcIdx, dstIdx) so
// receivers can verify byte-exact content via blobByte/blobStreamHash.
// Returns a stop function.
func startBlobServerOn(t *testing.T, eng *Engine, addrPort string, srcIdx, dstIdx, sizeBytes int) func() {
	t.Helper()
	ap := mustParseAddrPort(t, addrPort)
	ln, err := eng.ListenTCP(ap)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	stopped := atomic.Bool{}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go (&meshPeer{idx: srcIdx}).serveBlob(c, sizeBytes/1024)
			_ = dstIdx // dst is encoded in the request URL by the client
		}
	}()
	return func() {
		stopped.Store(true)
		_ = ln.Close()
	}
}

func mustParseAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ap
}

// fetchBlobAndVerify is the 2-peer counterpart of
// meshChaosNet.fetchAndVerify — same logic, single dialer.
func fetchBlobAndVerify(srcEng *Engine, addr string, srvSrcIdx, requestDstIdx, sizeBytes int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := retryMeshDialContextWithContext(ctx, srcEng, "tcp", addr, 30*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(120 * time.Second))
	req := []byte("GET /blob?dst=" + intToStr(requestDstIdx) + "&size=" + intToStr(sizeBytes) +
		" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	if _, err := conn.Write(req); err != nil {
		return err
	}
	body, err := readHTTPBody(conn)
	if err != nil {
		return err
	}
	if len(body) != sizeBytes {
		return errors.New("body length mismatch")
	}
	want := blobStreamHash(srvSrcIdx, requestDstIdx, sizeBytes)
	got := sha256Sum(body)
	if got != want {
		return errors.New("sha256 mismatch")
	}
	return nil
}

func intToStr(n int) string {
	return strconv.Itoa(n)
}

func sha256Sum(b []byte) [32]byte {
	return sha256.Sum256(b)
}

// testingChaosFlag returns true if the mesh-chaos gate is enabled via
// UWGS_RUN_MESH_CHAOS=1 env var, -uwgs-mesh-chaos CLI flag, or -uwgs-all.
func testingChaosFlag() bool {
	return testconfig.Get().MeshChaos
}

// TestMeshChaosResume_Foundation is the topology-only stage of the
// 5-peer mesh chaos test (full chaos lands in subsequent commits).
//
// Layout:
//
//	            hub (100.64.97.1, mesh-control + relay)
//	           /  |  |  |  \
//	         p1   p2 p3 p4   p5
//	      .10  .11 .12 .13   .14
//
// All five peers register with the hub via mesh-control, learn each
// other's endpoints + tunnel addresses, and (via forceMeshDynamic
// Active) flip every direct route to "preferred". Each peer hosts a
// tunnel-side HTTP server; each peer pulls a 1 MiB blob from every
// OTHER peer. 5×4 = 20 transfers run in parallel. Every blob is
// content-addressed (SHA256-keyed deterministic PRNG over (src,
// dst, offset)) so we detect any byte-level corruption.
//
// Subsequent commits add chaos:
//   - mid-flight P2P kill (force traffic to relay, TCP must resume)
//   - full WG outage for a few seconds (all transfers must survive)
//   - source-port randomization on reconnect (mesh-control relearn)
//   - TCP outer transport variant (handshake retry without stream
//     break)
//
// Gated by UWGS_RUN_MESH_CHAOS=1; -short skips it.
func TestMeshChaosResume_Foundation(t *testing.T) {
	if testing.Short() {
		t.Skip("mesh chaos test skipped in -short mode")
	}
	// Even without the env flag, we run the foundation case as a
	// smoke check (it's quick, ~5s) — the chaos layers themselves
	// are what take longer and are more env-flag-gated.

	const (
		nPeers     = 5
		blobSizeKB = 1024 // 1 MiB per (src,dst) pair; chaos commits scale up
	)
	mesh := setupMeshChaosTopology(t, nPeers)
	defer mesh.close()

	// Wait for every direct dynamic peer relationship to converge.
	mesh.waitFullMesh(t)

	// Start each peer's HTTP server.
	for i := range mesh.peers {
		mesh.startBlobServer(t, i, blobSizeKB)
	}

	// Run all 20 cross-pair transfers in parallel.
	mesh.runFullMeshTransfers(t, blobSizeKB)
}

// ----------------------------------------------------------------
// Topology setup
// ----------------------------------------------------------------

type meshPeer struct {
	idx   int    // 0..nPeers-1
	addr  string // "100.64.97.10"
	port  int    // tunnel-side HTTP server port
	eng   *Engine
	pubKey string
}

type meshChaosNet struct {
	hub       *Engine
	hubKey    string
	peers     []*meshPeer
	closeFns  []func()
}

func (m *meshChaosNet) close() {
	for _, fn := range m.closeFns {
		fn()
	}
	if m.hub != nil {
		m.hub.Close()
	}
	for _, p := range m.peers {
		if p.eng != nil {
			p.eng.Close()
		}
	}
}

func setupMeshChaosTopology(t *testing.T, nPeers int) *meshChaosNet {
	t.Helper()

	hubKey := mustMeshKey(t)
	hubPort := freeUDPPortTest(t)
	const subnet = "100.64.97."

	// Hub config: relay enabled, mesh-control listener.
	hubCfg := config.Default()
	hubCfg.WireGuard.PrivateKey = hubKey.String()
	hubCfg.WireGuard.ListenPort = &hubPort
	hubCfg.WireGuard.Addresses = []string{subnet + "1/32"}
	hubCfg.MeshControl.Listen = subnet + "1:8800"
	relay := true
	hubCfg.Relay.Enabled = &relay
	hubCfg.ACL.RelayDefault = acl.Allow

	peerKeys := make([]struct {
		priv, psk string
	}, nPeers)
	for i := 0; i < nPeers; i++ {
		k := mustMeshKey(t)
		psk := mustMeshKey(t)
		peerKeys[i].priv = k.String()
		peerKeys[i].psk = psk.String()
		hubCfg.WireGuard.Peers = append(hubCfg.WireGuard.Peers, config.Peer{
			PublicKey:      k.PublicKey().String(),
			PresharedKey:   psk.String(),
			AllowedIPs:     []string{fmt.Sprintf("%s%d/32", subnet, 10+i)},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
		})
	}

	hub := mustStartMeshEngine(t, hubCfg)

	mesh := &meshChaosNet{
		hub:    hub,
		hubKey: hubKey.PublicKey().String(),
		peers:  make([]*meshPeer, nPeers),
	}

	// Each peer dials the hub directly; the rest of the mesh is
	// learned at runtime via the mesh-control protocol.
	for i := 0; i < nPeers; i++ {
		idx := i
		// Parse the per-peer private key back from its base64
		// representation. We need it as wgtypes.Key for status
		// lookups via PublicKey().
		// (peerKeys[i].priv is already in the base64 form expected
		// by the engine; the engine itself parses it on Normalize.)
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = peerKeys[idx].priv
		cfg.WireGuard.Addresses = []string{fmt.Sprintf("%s%d/32", subnet, 10+idx)}
		// Allow this peer to reach every OTHER peer's tunnel addr
		// via the hub's relay until direct paths converge. Hub +
		// every other peer's tunnel CIDR.
		allowed := []string{subnet + "1/32"}
		for j := 0; j < nPeers; j++ {
			if j == idx {
				continue
			}
			allowed = append(allowed, fmt.Sprintf("%s%d/32", subnet, 10+j))
		}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           hubKey.PublicKey().String(),
			PresharedKey:        peerKeys[idx].psk,
			Endpoint:            "127.0.0.1:" + strconv.Itoa(hubPort),
			AllowedIPs:          allowed,
			PersistentKeepalive: 1,
			ControlURL:          "http://" + subnet + "1:8800",
			MeshEnabled:         true,
			MeshAcceptACLs:      true,
		}}
		eng := mustStartMeshEngine(t, cfg)
		mesh.peers[idx] = &meshPeer{
			idx:    idx,
			addr:   fmt.Sprintf("%s%d", subnet, 10+idx),
			port:   18080 + idx,
			eng:    eng,
			pubKey: meshPeerPubKey(t, peerKeys[idx].priv),
		}
	}

	// Wait for every peer's WG handshake with the hub to complete.
	for _, p := range mesh.peers {
		waitPeerHandshakeTest(t, mesh.hub, p.pubKey)
		waitPeerHandshakeTest(t, p.eng, mesh.hubKey)
	}

	// Kick off mesh-control polling on every peer so they discover
	// each other.
	for _, p := range mesh.peers {
		p.eng.runMeshPolling()
	}
	return mesh
}

// meshPeerPubKey extracts the public key from a base64 private key
// string. Used to wire up cross-peer status lookups.
func meshPeerPubKey(t *testing.T, privBase64 string) string {
	t.Helper()
	k, err := wgtypes.ParseKey(privBase64)
	if err != nil {
		t.Fatalf("parse private key: %v", err)
	}
	return k.PublicKey().String()
}

// ----------------------------------------------------------------
// Convergence assertion
// ----------------------------------------------------------------

func (m *meshChaosNet) waitFullMesh(t *testing.T) {
	t.Helper()
	// For every (i, j) pair where i != j, peer[i] must have learned
	// peer[j] as a dynamic peer, and we force the dynamic-active
	// flag so direct routes are preferred.
	for i, p := range m.peers {
		for j, q := range m.peers {
			if i == j {
				continue
			}
			waitDynamicPeerStatus(t, p.eng, q.pubKey)
			forceMeshDynamicActive(t, p.eng, q.pubKey)
		}
	}
}

// ----------------------------------------------------------------
// Workload: deterministic blob server + cross-mesh transfers
// ----------------------------------------------------------------

// blobByte returns a deterministic byte at offset for the (src, dst)
// pair. Same byte produced on both ends — sender writes, receiver
// reads + verifies, both compute it identically.
func blobByte(srcIdx, dstIdx, offset int) byte {
	// Mix the three parameters into a uint64 then take the low byte.
	// xorshift64* is sufficient determinism for content addressing.
	x := uint64(srcIdx)<<48 | uint64(dstIdx)<<32 | uint64(offset)
	x ^= x >> 12
	x *= 0x2545F4914F6CDD1D
	x ^= x >> 27
	return byte(x)
}

func blobStreamHash(srcIdx, dstIdx, sizeBytes int) [32]byte {
	h := sha256.New()
	buf := make([]byte, 4096)
	for written := 0; written < sizeBytes; written += len(buf) {
		n := len(buf)
		if written+n > sizeBytes {
			n = sizeBytes - written
		}
		for i := 0; i < n; i++ {
			buf[i] = blobByte(srcIdx, dstIdx, written+i)
		}
		h.Write(buf[:n])
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// startBlobServer puts an HTTP listener on the peer's tunnel
// address. Path /blob?dst=<idx>&size=<bytes> returns the
// deterministic blob for (this peer → dst). The server runs until
// the peer's engine is closed.
func (m *meshChaosNet) startBlobServer(t *testing.T, peerIdx int, sizeKB int) {
	t.Helper()
	p := m.peers[peerIdx]
	ap := netip.MustParseAddrPort(fmt.Sprintf("%s:%d", p.addr, p.port))
	ln, err := p.eng.ListenTCP(ap)
	if err != nil {
		t.Fatalf("peer %d ListenTCP %s: %v", peerIdx, ap, err)
	}
	m.closeFns = append(m.closeFns, func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serveBlob(conn, sizeKB)
		}
	}()
}

// serveBlob reads a one-line request "GET /blob?dst=N&size=B HTTP/1.1\r\n..."
// and streams the corresponding deterministic blob.
func (p *meshPeer) serveBlob(conn net.Conn, _ int) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	br := make([]byte, 4096)
	n, err := conn.Read(br)
	if err != nil || n == 0 {
		return
	}
	req := string(br[:n])
	// Cheap parse: find "dst=" and "size=" in the request line.
	dst := atoiKV(req, "dst=")
	size := atoiKV(req, "size=")
	if dst < 0 || size <= 0 {
		_, _ = io.WriteString(conn, "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")
		return
	}
	hdr := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", size)
	if _, err := io.WriteString(conn, hdr); err != nil {
		return
	}
	buf := make([]byte, 32*1024)
	for written := 0; written < size; {
		n := len(buf)
		if written+n > size {
			n = size - written
		}
		for i := 0; i < n; i++ {
			buf[i] = blobByte(p.idx, dst, written+i)
		}
		if _, err := conn.Write(buf[:n]); err != nil {
			return
		}
		written += n
	}
}

func atoiKV(req, key string) int {
	idx := indexOf(req, key)
	if idx < 0 {
		return -1
	}
	rest := req[idx+len(key):]
	end := 0
	for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
		end++
	}
	if end == 0 {
		return -1
	}
	v, err := strconv.Atoi(rest[:end])
	if err != nil {
		return -1
	}
	return v
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

// runFullMeshTransfers spawns 5×4=20 concurrent goroutines, each
// downloading a blob from src to dst, verifying SHA256.
func (m *meshChaosNet) runFullMeshTransfers(t *testing.T, sizeKB int) {
	t.Helper()
	sizeBytes := sizeKB * 1024
	var wg sync.WaitGroup
	failed := atomic.Int64{}
	type result struct{ src, dst int; ok bool; err string }
	results := make(chan result, len(m.peers)*(len(m.peers)-1))

	for srcIdx := range m.peers {
		for dstIdx := range m.peers {
			if srcIdx == dstIdx {
				continue
			}
			wg.Add(1)
			go func(src, dst int) {
				defer wg.Done()
				ok, msg := m.fetchAndVerify(src, dst, sizeBytes)
				if !ok {
					failed.Add(1)
				}
				results <- result{src: src, dst: dst, ok: ok, err: msg}
			}(srcIdx, dstIdx)
		}
	}
	wg.Wait()
	close(results)

	for r := range results {
		if !r.ok {
			t.Errorf("transfer src=%d→dst=%d FAILED: %s", r.src, r.dst, r.err)
		}
	}
	if got := failed.Load(); got > 0 {
		t.Fatalf("%d transfer failures across the 5-peer full mesh", got)
	}
	t.Logf("foundation: 5×4 = 20 transfers × %d KiB = %d MiB cross-mesh, all bytes verified",
		sizeKB, len(m.peers)*(len(m.peers)-1)*sizeKB/1024)
}

// fetchAndVerify pulls a blob from peer[dst] (acting as the HTTP
// server) and verifies the byte-stream hash matches the expected
// (src, dst, size) deterministic PRNG. The "src" peer is the one
// initiating the request — its dialer is what we exercise.
func (m *meshChaosNet) fetchAndVerify(srcIdx, dstIdx, sizeBytes int) (bool, string) {
	srcPeer := m.peers[srcIdx]
	dstPeer := m.peers[dstIdx]
	addr := fmt.Sprintf("%s:%d", dstPeer.addr, dstPeer.port)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := retryMeshDialContextWithContext(ctx, srcPeer.eng, "tcp", addr, 30*time.Second)
	if err != nil {
		return false, fmt.Sprintf("dial: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(60 * time.Second))
	req := fmt.Sprintf("GET /blob?dst=%d&size=%d HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
		srcIdx, sizeBytes)
	if _, err := io.WriteString(conn, req); err != nil {
		return false, fmt.Sprintf("write request: %v", err)
	}
	// Read the HTTP response: skip headers, read body, hash it.
	body, err := readHTTPBody(conn)
	if err != nil {
		return false, fmt.Sprintf("read body: %v", err)
	}
	if len(body) != sizeBytes {
		return false, fmt.Sprintf("body len %d, want %d", len(body), sizeBytes)
	}
	// Server sees the request as "(server-peer-idx, requested-dst-idx)"
	// = (dstIdx, srcIdx). Hash from the server's perspective.
	want := blobStreamHash(dstIdx, srcIdx, sizeBytes)
	got := sha256.Sum256(body)
	if got != want {
		return false, fmt.Sprintf("sha256 mismatch")
	}
	return true, ""
}

// readHTTPBody reads minimal HTTP response framing — Content-Length
// only, no chunked. Sufficient for our tiny test server.
func readHTTPBody(conn net.Conn) ([]byte, error) {
	// Read until \r\n\r\n.
	hdrBuf := make([]byte, 0, 1024)
	tmp := make([]byte, 256)
	contentLen := -1
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			hdrBuf = append(hdrBuf, tmp[:n]...)
			if i := indexOf(string(hdrBuf), "\r\n\r\n"); i >= 0 {
				// Parse Content-Length out of the header bytes.
				header := string(hdrBuf[:i])
				clIdx := indexOf(header, "Content-Length:")
				if clIdx < 0 {
					return nil, fmt.Errorf("no Content-Length")
				}
				rest := header[clIdx+len("Content-Length:"):]
				// strip leading whitespace
				for len(rest) > 0 && (rest[0] == ' ' || rest[0] == '\t') {
					rest = rest[1:]
				}
				end := 0
				for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
					end++
				}
				v, err := strconv.Atoi(rest[:end])
				if err != nil {
					return nil, err
				}
				contentLen = v
				// Body bytes already buffered: hdrBuf[i+4:].
				body := make([]byte, 0, contentLen)
				body = append(body, hdrBuf[i+4:]...)
				for len(body) < contentLen {
					n, err := conn.Read(tmp)
					if n > 0 {
						body = append(body, tmp[:n]...)
					}
					if err != nil && len(body) < contentLen {
						return body, err
					}
				}
				return body[:contentLen], nil
			}
		}
		if err != nil {
			return nil, err
		}
	}
}
