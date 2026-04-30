// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package soak

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/testconfig"
	"golang.org/x/net/proxy"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLoopbackSOCKSSoak(t *testing.T) {
	tcfg := testconfig.Get()
	if !tcfg.Soak {
		t.Skip("set UWGS_SOAK=1 or -uwgs-soak to run long soak tests")
	}
	duration := 2 * time.Minute
	if tcfg.SoakSeconds > 0 {
		duration = time.Duration(tcfg.SoakSeconds) * time.Second
	}

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.91.0.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.91.0.2/32"},
	}}
	server := mustStartEngine(t, serverCfg)

	ln, err := server.ListenTCP(netip.MustParseAddrPort("100.91.0.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveEcho(ln)

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.91.0.2/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            fmt.Sprintf("127.0.0.1:%d", serverPort),
		AllowedIPs:          []string{"100.91.0.1/32"},
		PersistentKeepalive: 1,
	}}
	clientCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	client := mustStartEngine(t, clientCfg)

	dialer, err := proxy.SOCKS5("tcp", client.Addr("socks5"), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	const workers = 8
	payload := bytes.Repeat([]byte("soak"), 16*1024)
	var wg sync.WaitGroup
	errc := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for ctx.Err() == nil {
				conn, err := dialer.Dial("tcp", "100.91.0.1:18080")
				if err != nil {
					errc <- fmt.Errorf("worker %d dial: %w", id, err)
					return
				}
				_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
				if _, err := conn.Write(payload); err != nil {
					_ = conn.Close()
					errc <- fmt.Errorf("worker %d write: %w", id, err)
					return
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(conn, got); err != nil {
					_ = conn.Close()
					errc <- fmt.Errorf("worker %d read: %w", id, err)
					return
				}
				_ = conn.Close()
				if !bytes.Equal(got, payload) {
					errc <- fmt.Errorf("worker %d echo mismatch", id)
					return
				}
			}
		}(i)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-errc:
			t.Fatal(err)
		case <-ticker.C:
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			status, _ := client.Status()
			t.Logf("soak: goroutines=%d heap=%d active_connections=%d", runtime.NumGoroutine(), mem.Alloc, status.ActiveConnections)
		case <-done:
			return
		case <-ctx.Done():
			wg.Wait()
			return
		}
	}
}

func TestLoopbackImpairedChattySOCKSSoak(t *testing.T) {
	tcfg := testconfig.Get()
	if !tcfg.Soak {
		t.Skip("set UWGS_SOAK=1 or -uwgs-soak to run long soak tests")
	}
	duration := 2 * time.Minute
	if tcfg.SoakSeconds > 0 {
		duration = time.Duration(tcfg.SoakSeconds) * time.Second
	}

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.91.1.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.91.1.2/32"},
	}}
	server := mustStartEngine(t, serverCfg)

	ln, err := server.ListenTCP(netip.MustParseAddrPort("100.91.1.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveEcho(ln)

	impair, err := newUDPImpairProxy(netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", serverPort)))
	if err != nil {
		t.Fatal(err)
	}
	defer impair.close()

	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.91.1.2/32"}
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            impair.addr(),
		AllowedIPs:          []string{"100.91.1.1/32"},
		PersistentKeepalive: 1,
	}}
	clientCfg.Proxy.SOCKS5 = "127.0.0.1:0"
	client := mustStartEngine(t, clientCfg)

	dialer, err := proxy.SOCKS5("tcp", client.Addr("socks5"), nil, proxy.Direct)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), duration)
	defer cancel()
	const workers = 6
	var wg sync.WaitGroup
	errc := make(chan error, workers)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			rng := rand.New(rand.NewSource(int64(1000 + id)))
			for ctx.Err() == nil {
				conn, err := dialer.Dial("tcp", "100.91.1.1:18080")
				if err != nil {
					errc <- fmt.Errorf("worker %d dial: %w", id, err)
					return
				}
				_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
				for j := 0; j < 200 && ctx.Err() == nil; j++ {
					payload := bytes.Repeat([]byte{byte(id), byte(j)}, 1+rng.Intn(96))
					if _, err := conn.Write(payload); err != nil {
						_ = conn.Close()
						errc <- fmt.Errorf("worker %d write: %w", id, err)
						return
					}
					got := make([]byte, len(payload))
					if _, err := io.ReadFull(conn, got); err != nil {
						_ = conn.Close()
						errc <- fmt.Errorf("worker %d read: %w", id, err)
						return
					}
					if !bytes.Equal(got, payload) {
						_ = conn.Close()
						errc <- fmt.Errorf("worker %d echo mismatch", id)
						return
					}
					if rng.Intn(25) == 0 {
						time.Sleep(time.Duration(rng.Intn(5)) * time.Millisecond)
					}
				}
				_ = conn.Close()
			}
		}(i)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case err := <-errc:
			t.Fatal(err)
		case <-ticker.C:
			var mem runtime.MemStats
			runtime.ReadMemStats(&mem)
			status, _ := client.Status()
			t.Logf("impaired soak: goroutines=%d heap=%d active_connections=%d proxy_pending=%d", runtime.NumGoroutine(), mem.Alloc, status.ActiveConnections, impair.pendingCount())
		case <-done:
			return
		case <-ctx.Done():
			wg.Wait()
			return
		}
	}
}

func mustStartEngine(t testing.TB, cfg config.Config) *engine.Engine {
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
	t.Cleanup(func() { _ = eng.Close() })
	return eng
}

func mustKey(t testing.TB) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func freeUDPPort(t testing.TB) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func serveEcho(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_, _ = io.Copy(conn, conn)
		}()
	}
}

type udpImpairProxy struct {
	pc     *net.UDPConn
	server netip.AddrPort

	mu        sync.Mutex
	client    netip.AddrPort
	hasClient bool
	rng       *rand.Rand
	pending   int
}

func newUDPImpairProxy(server netip.AddrPort) (*udpImpairProxy, error) {
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return nil, err
	}
	p := &udpImpairProxy{
		pc:     pc,
		server: server,
		rng:    rand.New(rand.NewSource(1)),
	}
	go p.loop()
	return p, nil
}

func (p *udpImpairProxy) addr() string {
	return p.pc.LocalAddr().String()
}

func (p *udpImpairProxy) close() {
	_ = p.pc.Close()
}

func (p *udpImpairProxy) pendingCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.pending
}

func (p *udpImpairProxy) loop() {
	for {
		buf := make([]byte, 64*1024)
		n, addr, err := p.pc.ReadFromUDPAddrPort(buf)
		if err != nil {
			return
		}
		dst, ok, delay := p.routeAndImpair(addr)
		if !ok {
			continue
		}
		packet := append([]byte(nil), buf[:n]...)
		go func() {
			defer p.finishPending()
			time.Sleep(delay)
			_, _ = p.pc.WriteToUDPAddrPort(packet, dst)
		}()
	}
}

func (p *udpImpairProxy) routeAndImpair(src netip.AddrPort) (netip.AddrPort, bool, time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	var dst netip.AddrPort
	if src == p.server {
		if !p.hasClient {
			return netip.AddrPort{}, false, 0
		}
		dst = p.client
	} else {
		p.client = src
		p.hasClient = true
		dst = p.server
	}
	if p.pending > 96 {
		return netip.AddrPort{}, false, 0
	}
	loss := 0.003 + float64(time.Now().Unix()%5)*0.004
	if p.rng.Float64() < loss {
		return netip.AddrPort{}, false, 0
	}
	delay := time.Duration(p.rng.Intn(20)) * time.Millisecond
	if p.rng.Intn(80) == 0 {
		delay += time.Duration(50+p.rng.Intn(150)) * time.Millisecond
	}
	p.pending++
	return dst, true, delay
}

func (p *udpImpairProxy) finishPending() {
	p.mu.Lock()
	if p.pending > 0 {
		p.pending--
	}
	p.mu.Unlock()
}
