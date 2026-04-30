// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build !lite && !race

package engine

import (
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/acl"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/transport"
)

// TestMeshChaosResume_TCPOuterMidStreamDrop pins the TCP-outer
// transport's reconnect-and-resume path. Production trigger:
// hostile networks where UDP is blocked or rate-limited and
// WireGuard's outer layer rides TCP — a stream that gets killed
// (carrier reset, idle prune, transparent middlebox kill) MUST
// be re-dialed by the transport layer without losing the WG
// session, and mesh-control + tunnel traffic must resume on its
// own.
//
// Topology:
//
//	      ┌─────────────┐
//	      │     hub     │ TCP listener (tcp base transport)
//	      └──────┬──────┘
//	             │
//	      ┌──────┴──────┐
//	      │  tcpChaosProxy ── DropAllConnections() forces a kill
//	      └──────┬──────┘
//	         ┌───┴───┐
//	         │       │
//	      ┌──┴──┐ ┌──┴──┐
//	      │  A  │ │  B  │  TCP-client transport, peer.Endpoint = proxy
//	      └─────┘ └─────┘
//
// Sequence:
//  1. Bring up hub (TCP listener), proxy, A, B (both TCP clients).
//  2. Wait for WG handshakes. Verify A↔B relay traffic works.
//  3. proxy.DropAllConnections() — kills every active TCP stream.
//  4. WG-over-TCP transport's reconnect machinery MUST re-dial.
//  5. After reconnect window, A↔B relay traffic resumes byte-exact.
//
// Wall: ~10-30s (handshake + reconnect timer + transfer).
//
// Gated by UWGS_RUN_MESH_CHAOS=1 + -short skip + !lite + !race.
func TestMeshChaosResume_TCPOuterMidStreamDrop(t *testing.T) {
	if testing.Short() {
		t.Skip("mesh chaos test skipped in -short mode")
	}
	if !testingChaosFlag() {
		t.Skip("set UWGS_RUN_MESH_CHAOS=1 or -uwgs-mesh-chaos to run TCP-outer chaos test")
	}

	hubKey := mustMeshKey(t)
	keyA := mustMeshKey(t)
	keyB := mustMeshKey(t)
	hubTCPPort := freeTCPPortMesh(t)

	pskA := mustMeshKey(t).String()
	pskB := mustMeshKey(t).String()

	// Hub: TCP listener for WG outer + mesh-control + relay.
	hubCfg := config.Default()
	hubCfg.WireGuard.PrivateKey = hubKey.String()
	hubCfg.WireGuard.Addresses = []string{"100.64.102.1/32"}
	hubCfg.MeshControl.Listen = "100.64.102.1:8804"
	relay := true
	hubCfg.Relay.Enabled = &relay
	hubCfg.ACL.RelayDefault = acl.Allow
	hubCfg.Transports = []transport.Config{{
		Name:       "hub-tcp",
		Base:       "tcp",
		Listen:     true,
		ListenPort: &hubTCPPort,
	}}
	hubCfg.WireGuard.Peers = []config.Peer{
		{
			PublicKey:      keyA.PublicKey().String(),
			PresharedKey:   pskA,
			AllowedIPs:     []string{"100.64.102.2/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
			Transport:      "hub-tcp",
		},
		{
			PublicKey:      keyB.PublicKey().String(),
			PresharedKey:   pskB,
			AllowedIPs:     []string{"100.64.102.3/32"},
			MeshEnabled:    true,
			MeshAcceptACLs: true,
			Transport:      "hub-tcp",
		},
	}
	hub := mustStartMeshEngine(t, hubCfg)
	defer hub.Close()

	// TCP middleman: clients dial proxy.Addr; proxy forwards to hub.
	// DropAllConnections() kills every active forwarding pair, which
	// is the chaos lever this test pulls.
	proxy, err := startTCPChaosProxy(fmt.Sprintf("127.0.0.1:%d", hubTCPPort))
	if err != nil {
		t.Fatalf("start tcp chaos proxy: %v", err)
	}
	defer proxy.Close()

	clientCfg := func(priv, addr, otherAddr, psk string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = priv
		cfg.WireGuard.Addresses = []string{addr}
		cfg.Transports = []transport.Config{{
			Name: "cli-tcp",
			Base: "tcp",
		}}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           hubKey.PublicKey().String(),
			PresharedKey:        psk,
			Endpoint:            proxy.Addr(),
			AllowedIPs:          []string{"100.64.102.1/32", otherAddr},
			PersistentKeepalive: 1,
			ControlURL:          "http://100.64.102.1:8804",
			MeshEnabled:         true,
			MeshAcceptACLs:      true,
			Transport:           "cli-tcp",
		}}
		return cfg
	}

	engA := mustStartMeshEngine(t, clientCfg(
		keyA.String(), "100.64.102.2/32", "100.64.102.3/32", pskA,
	))
	defer engA.Close()
	engB := mustStartMeshEngine(t, clientCfg(
		keyB.String(), "100.64.102.3/32", "100.64.102.2/32", pskB,
	))
	defer engB.Close()

	waitPeerHandshakeTest(t, hub, keyA.PublicKey().String())
	waitPeerHandshakeTest(t, hub, keyB.PublicKey().String())
	waitPeerHandshakeTest(t, engA, hubKey.PublicKey().String())
	waitPeerHandshakeTest(t, engB, hubKey.PublicKey().String())

	// Mesh polling.
	engA.runMeshPolling()
	engB.runMeshPolling()
	waitDynamicPeerStatus(t, engA, keyB.PublicKey().String())
	waitDynamicPeerStatus(t, engB, keyA.PublicKey().String())

	// Sanity: TCP outer is actually carrying handshake bytes.
	if cfwd := proxy.BytesForwarded(); cfwd == 0 {
		t.Fatalf("tcp chaos proxy didn't forward any bytes — TCP outer wasn't engaged")
	}

	// Baseline relay transfer A → B works. Keep the blob server up
	// across the kill — gVisor netstack holds the listening port
	// briefly after Close, so re-binding 18080 mid-test races. The
	// listener is fine to leave running; we only care that the
	// post-reconnect fetch succeeds.
	const blobBytes = 256 * 1024
	stopFn := startBlobServerOn(t, engB, "100.64.102.3:18080", 0, 1, blobBytes)
	defer stopFn()
	if err := fetchBlobAndVerify(engA, "100.64.102.3:18080", 0, 1, blobBytes); err != nil {
		t.Fatalf("baseline TCP-outer A→B transfer failed: %v", err)
	}

	bytesBeforeKill := proxy.BytesForwarded()

	// === CHAOS: kill all TCP connections ===
	// Both A→hub and B→hub TCP streams drop. The transport's
	// reconnect logic must re-dial; WG re-handshakes; mesh
	// polling resumes; relay traffic continues.
	proxy.DropAllConnections()
	t.Logf("dropped all TCP connections after %d bytes forwarded", bytesBeforeKill)

	// Wait for both clients to re-establish handshakes via the
	// reconnected TCP streams. PersistentKeepalive=1s drives the
	// re-handshake quickly once the transport reconnects.
	waitPeerHandshakeTest(t, hub, keyA.PublicKey().String())
	waitPeerHandshakeTest(t, hub, keyB.PublicKey().String())
	waitPeerHandshakeTest(t, engA, hubKey.PublicKey().String())
	waitPeerHandshakeTest(t, engB, hubKey.PublicKey().String())

	// Sanity: bytes are flowing again post-reconnect.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if proxy.BytesForwarded() > bytesBeforeKill {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	bytesAfterReconnect := proxy.BytesForwarded()
	if bytesAfterReconnect <= bytesBeforeKill {
		t.Fatalf("after dropping all connections, no new bytes were forwarded (before=%d after=%d) — TCP outer didn't reconnect",
			bytesBeforeKill, bytesAfterReconnect)
	}

	// Final invariant: relay transfer still works after the kill.
	if err := fetchBlobAndVerify(engA, "100.64.102.3:18080", 0, 1, blobBytes); err != nil {
		t.Fatalf("post-reconnect TCP-outer A→B transfer failed: %v", err)
	}

	t.Logf("TCP-outer mid-stream-drop chaos: pre-kill=%d bytes, post-reconnect=%d bytes; relay traffic resumed byte-exact",
		bytesBeforeKill, bytesAfterReconnect)
}

// tcpChaosProxy is a TCP middleman that bidirectionally forwards
// every accepted client connection to a fixed upstream address.
// DropAllConnections() closes every active forwarding pair, used
// by the chaos test to simulate a transparent middlebox kill.
type tcpChaosProxy struct {
	listener      net.Listener
	upstream      string
	mu            sync.Mutex
	activeConns   []net.Conn // both client and upstream sides; close all to kill
	bytesForward  atomic.Int64
	closeOnce     sync.Once
	closed        chan struct{}
	listenerError atomic.Pointer[error]
}

func startTCPChaosProxy(upstream string) (*tcpChaosProxy, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	p := &tcpChaosProxy{
		listener: ln,
		upstream: upstream,
		closed:   make(chan struct{}),
	}
	go p.acceptLoop()
	return p, nil
}

func (p *tcpChaosProxy) Addr() string {
	return p.listener.Addr().String()
}

func (p *tcpChaosProxy) BytesForwarded() int64 {
	return p.bytesForward.Load()
}

func (p *tcpChaosProxy) Close() error {
	p.closeOnce.Do(func() {
		close(p.closed)
		_ = p.listener.Close()
		p.DropAllConnections()
	})
	return nil
}

// DropAllConnections closes every forwarding pair currently
// open. New incoming connections after this call are accepted
// normally (we don't tear the listener down) — the test wants a
// transient kill, not a permanent partition.
func (p *tcpChaosProxy) DropAllConnections() {
	p.mu.Lock()
	conns := p.activeConns
	p.activeConns = nil
	p.mu.Unlock()
	for _, c := range conns {
		_ = c.Close()
	}
}

func (p *tcpChaosProxy) acceptLoop() {
	for {
		client, err := p.listener.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				p.listenerError.Store(&err)
			}
			return
		}
		go p.handle(client)
	}
}

func (p *tcpChaosProxy) handle(client net.Conn) {
	upstream, err := net.DialTimeout("tcp", p.upstream, 5*time.Second)
	if err != nil {
		_ = client.Close()
		return
	}
	p.mu.Lock()
	p.activeConns = append(p.activeConns, client, upstream)
	p.mu.Unlock()

	// Bidirectional copy. Either side closing tears down both.
	done := make(chan struct{}, 2)
	go p.copyAndCount(upstream, client, done) // client → upstream
	go p.copyAndCount(client, upstream, done) // upstream → client
	<-done
	_ = client.Close()
	_ = upstream.Close()
}

func (p *tcpChaosProxy) copyAndCount(dst io.Writer, src io.Reader, done chan<- struct{}) {
	buf := make([]byte, 32*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			if _, werr := dst.Write(buf[:n]); werr != nil {
				done <- struct{}{}
				return
			}
			p.bytesForward.Add(int64(n))
		}
		if err != nil {
			done <- struct{}{}
			return
		}
	}
}

// freeTCPPortMesh is a TCP-port equivalent of freeUDPPortTest used
// by mesh tests. We use a distinct name to avoid colliding with any
// freeTCPPort helper that might exist in another _test.go in this
// package (Go allows it but keeping names distinct avoids surprise).
func freeTCPPortMesh(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	defer ln.Close()
	return ln.Addr().(*net.TCPAddr).Port
}
