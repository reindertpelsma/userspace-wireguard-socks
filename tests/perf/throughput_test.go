// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build perf

// Package perf holds the performance baseline harness for uwgsocks.
//
// This file is gated by both `//go:build perf` AND a runtime check
// for `UWGS_PERF=1`. Belt-and-suspenders: no contributor running
// `go test ./...` ever pays the perf cost, and even when someone
// builds with `-tags perf` they still need the env var set to
// actually run a benchmark. Default `go test` / fuzz / stress / soak
// runs are completely unaffected.
//
// What this package measures:
//
//   - Tunnel TCP throughput end-to-end under loopback (two engines
//     in the same process, hub-relay topology).
//   - Per-connection latency p50/p95/p99 under steady load.
//   - Per-byte CPU cost (rough proxy via runtime.ReadMemStats +
//     time.ProcessTime).
//
// What this package does NOT measure:
//
//   - Anything that requires kernel TUN (would need root).
//   - Real-network bandwidth (loopback is a fixed reference;
//     real-network runs go through tests/perf/scripts/).
//
// Output: a markdown row per workload, suitable for pasting into
// docs/performance.md. The format is stable so multiple runs can
// be diffed.
package perf

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"sync/atomic"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// requirePerfEnv gates every test in this file behind UWGS_PERF=1 / -uwgs-perf.
// Without it, a test running under `-tags perf` still skips. This
// keeps an accidental `go test -tags perf ./...` from spending real
// time.
func requirePerfEnv(t *testing.T) {
	t.Helper()
	if !testconfig.Get().Perf {
		t.Skip("perf tests gated by UWGS_PERF=1 or -uwgs-perf; not set")
	}
}

// TestPerfTunnelTCPThroughput measures sustained TCP throughput
// across a 2-peer loopback topology — peer A → peer B over the
// userspace WG tunnel, both engines in the same process.
//
// Reference workload size: 256 MiB total; chunked into 64 KiB
// writes. Long enough to amortise WG handshake + first-packet
// latency, short enough that the 30s default test timeout is
// comfortable.
func TestPerfTunnelTCPThroughput(t *testing.T) {
	requirePerfEnv(t)

	const (
		totalBytes = 256 * 1024 * 1024 // 256 MiB
		chunkBytes = 64 * 1024
		runs       = 5
	)

	results := make([]float64, 0, runs)
	for run := 0; run < runs; run++ {
		mbps := runOneTCPThroughputPass(t, totalBytes, chunkBytes)
		results = append(results, mbps)
	}

	sort.Float64s(results)
	median := results[runs/2]
	min := results[0]
	max := results[runs-1]

	emitMarkdownRow(t, "Tunnel TCP throughput (loopback, 2-peer)",
		fmt.Sprintf("%.0f MiB", float64(totalBytes)/(1<<20)),
		fmt.Sprintf("%.0f MiB/s", median),
		fmt.Sprintf("%.0f MiB/s (min)", min),
		fmt.Sprintf("%.0f MiB/s (max)", max),
		runtime.GOOS+"/"+runtime.GOARCH,
	)
}

// TestPerfTunnelTCPLatency measures per-request RTT under a steady
// 100-byte ping/pong workload over the tunnel. The point isn't to
// measure the absolute latency floor (loopback is dominated by
// scheduler quanta) — it's to surface regressions when a refactor
// introduces a copy or a lock on the hot path.
func TestPerfTunnelTCPLatency(t *testing.T) {
	requirePerfEnv(t)

	const (
		iterations = 1000
		payload    = 100
	)

	hub, engA, engB := bringUpTwoPeerLoopback(t)
	defer engA.Close()
	defer engB.Close()
	defer hub.Close()

	srvAddr := "100.64.110.3:18080"
	stop := startEchoServer(t, engB, srvAddr)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	conn, err := dialWithRetry(ctx, engA, srvAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, payload)
	for i := range buf {
		buf[i] = byte(i)
	}
	rcv := make([]byte, payload)

	rtts := make([]time.Duration, 0, iterations)
	// Warm up: 50 round-trips before measuring.
	for i := 0; i < 50; i++ {
		conn.Write(buf)
		io.ReadFull(conn, rcv)
	}
	for i := 0; i < iterations; i++ {
		start := time.Now()
		if _, err := conn.Write(buf); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := io.ReadFull(conn, rcv); err != nil {
			t.Fatalf("read: %v", err)
		}
		rtts = append(rtts, time.Since(start))
	}

	sort.Slice(rtts, func(i, j int) bool { return rtts[i] < rtts[j] })
	p50 := rtts[iterations*50/100]
	p95 := rtts[iterations*95/100]
	p99 := rtts[iterations*99/100]

	emitMarkdownRow(t, "Tunnel TCP latency (loopback, 100 B ping)",
		fmt.Sprintf("%d iters", iterations),
		fmt.Sprintf("p50=%v", p50),
		fmt.Sprintf("p95=%v", p95),
		fmt.Sprintf("p99=%v", p99),
		runtime.GOOS+"/"+runtime.GOARCH,
	)
}

// runOneTCPThroughputPass brings up a fresh 2-peer topology, runs a
// blob transfer, and returns MiB/s.
func runOneTCPThroughputPass(t *testing.T, totalBytes, chunkBytes int) float64 {
	t.Helper()
	hub, engA, engB := bringUpTwoPeerLoopback(t)
	defer engA.Close()
	defer engB.Close()
	defer hub.Close()

	srvAddr := "100.64.110.3:18080"
	stop := startBlobServer(t, engB, srvAddr, totalBytes)
	defer stop()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	conn, err := dialWithRetry(ctx, engA, srvAddr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(fmt.Sprintf("GET %d\n", totalBytes))); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, chunkBytes)
	start := time.Now()
	got := 0
	for got < totalBytes {
		n, err := conn.Read(buf)
		if n > 0 {
			got += n
		}
		if err != nil {
			if got == totalBytes {
				break
			}
			t.Fatalf("read: %v at %d/%d", err, got, totalBytes)
		}
	}
	elapsed := time.Since(start)
	mbps := float64(totalBytes) / elapsed.Seconds() / (1 << 20)
	t.Logf("pass: %.0f MiB in %v = %.0f MiB/s", float64(totalBytes)/(1<<20), elapsed, mbps)
	return mbps
}

// bringUpTwoPeerLoopback creates a hub + two clients (A, B) all on
// loopback. Returns the three engines.
func bringUpTwoPeerLoopback(t *testing.T) (*engine.Engine, *engine.Engine, *engine.Engine) {
	t.Helper()
	hubKey := mustKey(t)
	keyA := mustKey(t)
	keyB := mustKey(t)
	hubPort := freeUDPPort(t)

	hubCfg := config.Default()
	hubCfg.WireGuard.PrivateKey = hubKey.String()
	hubCfg.WireGuard.ListenPort = &hubPort
	hubCfg.WireGuard.Addresses = []string{"100.64.110.1/32"}
	relay := true
	hubCfg.Relay.Enabled = &relay
	hubCfg.ACL.RelayDefault = "allow"
	hubCfg.WireGuard.Peers = []config.Peer{
		{PublicKey: keyA.PublicKey().String(), AllowedIPs: []string{"100.64.110.2/32"}},
		{PublicKey: keyB.PublicKey().String(), AllowedIPs: []string{"100.64.110.3/32"}},
	}
	hub := mustStart(t, hubCfg)

	mkClient := func(priv, addr, otherAddr string) config.Config {
		cfg := config.Default()
		cfg.WireGuard.PrivateKey = priv
		cfg.WireGuard.Addresses = []string{addr}
		cfg.WireGuard.Peers = []config.Peer{{
			PublicKey:           hubKey.PublicKey().String(),
			Endpoint:            fmt.Sprintf("127.0.0.1:%d", hubPort),
			AllowedIPs:          []string{"100.64.110.1/32", otherAddr},
			PersistentKeepalive: 1,
		}}
		return cfg
	}
	engA := mustStart(t, mkClient(keyA.String(), "100.64.110.2/32", "100.64.110.3/32"))
	engB := mustStart(t, mkClient(keyB.String(), "100.64.110.3/32", "100.64.110.2/32"))

	// Wait for handshakes by polling. 5 seconds is plenty on loopback.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		stA, _ := engA.Status()
		stB, _ := engB.Status()
		aHas := false
		bHas := false
		for _, p := range stA.Peers {
			if p.HasHandshake {
				aHas = true
			}
		}
		for _, p := range stB.Peers {
			if p.HasHandshake {
				bHas = true
			}
		}
		if aHas && bHas {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return hub, engA, engB
}

// startBlobServer spawns a tunnel-side TCP server that responds to
// "GET <bytes>\n" with the requested number of bytes (deterministic
// content, sha256-keyed).
func startBlobServer(t *testing.T, eng *engine.Engine, addrPort string, totalBytes int) func() {
	t.Helper()
	ap, err := parseAddrPort(addrPort)
	if err != nil {
		t.Fatalf("parse %q: %v", addrPort, err)
	}
	ln, err := eng.ListenTCP(ap)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
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
				h := sha256.New()
				buf := make([]byte, 64*1024)
				h.Write([]byte("perf-blob-stream-v1"))
				stream := h.Sum(nil)
				// Read the request header.
				rbuf := make([]byte, 64)
				n, _ := c.Read(rbuf)
				_ = n
				written := 0
				for written < totalBytes {
					for i := range buf {
						buf[i] = stream[(written+i)%len(stream)]
					}
					send := len(buf)
					if remaining := totalBytes - written; remaining < send {
						send = remaining
					}
					nw, err := c.Write(buf[:send])
					if err != nil {
						return
					}
					written += nw
				}
			}(c)
		}
	}()
	return func() {
		stopped.Store(true)
		_ = ln.Close()
	}
}

// startEchoServer spawns a tunnel-side TCP echo for latency tests.
func startEchoServer(t *testing.T, eng *engine.Engine, addrPort string) func() {
	t.Helper()
	ap, err := parseAddrPort(addrPort)
	if err != nil {
		t.Fatalf("parse %q: %v", addrPort, err)
	}
	ln, err := eng.ListenTCP(ap)
	if err != nil {
		t.Fatalf("ListenTCP: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}(c)
		}
	}()
	return func() { _ = ln.Close() }
}

func dialWithRetry(ctx context.Context, eng *engine.Engine, addr string) (net.Conn, error) {
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(15 * time.Second)
	}
	var last error
	for time.Now().Before(deadline) {
		dc, cancel := context.WithTimeout(ctx, 1*time.Second)
		conn, err := eng.DialContext(dc, "tcp", addr)
		cancel()
		if err == nil {
			return conn, nil
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	return nil, last
}

// emitMarkdownRow prints a tab-separated line + a markdown row to
// stdout, prefixed by a marker so a wrapping shell script can grep
// it out.
func emitMarkdownRow(t *testing.T, name, size, primary, secondary, tertiary, host string) {
	t.Helper()
	const marker = "PERFRESULT:"
	t.Logf("%s %s | %s | %s | %s | %s | %s",
		marker, name, size, primary, secondary, tertiary, host)
	t.Logf("MARKDOWN: | %s | %s | %s | %s | %s | %s |",
		host, name, size, primary, secondary, tertiary)
}

// ---- helpers shared with internal/engine tests but local here ----

// mustStart constructs an engine. Local copy because this package
// can't import the test-only helpers under internal/engine_test.
func mustStart(t *testing.T, cfg config.Config) *engine.Engine {
	t.Helper()
	if err := cfg.Normalize(); err != nil {
		t.Fatal(err)
	}
	eng, err := engine.New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	if err := eng.Start(); err != nil {
		_ = eng.Close()
		t.Fatal(err)
	}
	return eng
}

func mustKey(t *testing.T) wgtypes.Key {
	t.Helper()
	k, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.LocalAddr().(*net.UDPAddr).Port
}

func parseAddrPort(s string) (netip.AddrPort, error) {
	return netip.ParseAddrPort(s)
}
