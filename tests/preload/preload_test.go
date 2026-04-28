// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/fdproxy"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

func TestLDPreloadManagedTCPUDPConnect(t *testing.T) {
	if testing.Short() {
		t.Skip("LD_PRELOAD integration test skipped in -short mode")
	}
	if runtime.GOOS != "linux" {
		t.Skip("LD_PRELOAD wrapper is Linux-only")
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc is required for the preload integration test")
	}
	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()
	preloadSO := filepath.Join(tmp, "uwgpreload.so")
	stubBin := filepath.Join(tmp, "stub_client")
	run(t, repo, "gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-o", preloadSO, "preload/uwgpreload.c", "-ldl", "-pthread", "-lpthread")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", stubBin, "tests/preload/testdata/stub_client.c")

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)
	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.94.1/32"}
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.94.2/32"},
	}}
	serverEng := mustStart(t, serverCfg)

	apiSock := filepath.Join(tmp, "api.sock")
	httpSock := filepath.Join(tmp, "http.sock")
	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.94.2/32"}
	clientCfg.API.Listen = "unix:" + apiSock
	clientCfg.API.AllowUnauthenticatedUnix = true
	clientCfg.Proxy.HTTPListeners = []string{"unix:" + httpSock}
	clientCfg.SocketAPI.Bind = true
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            net.JoinHostPort("127.0.0.1", itoa(serverPort)),
		AllowedIPs:          []string{"100.64.94.1/32"},
		PersistentKeepalive: 1,
	}}
	clientEng := mustStart(t, clientCfg)
	_ = clientEng
	waitPath(t, httpSock)

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.94.1:18080"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveEchoListener(ln)

	udp, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.94.1:18081"))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go serveUDPEcho(udp)

	fdSock := filepath.Join(tmp, "fdproxy.sock")
	proxy, err := fdproxy.ListenWithSocketPath(fdSock, "unix:"+httpSock, "", "/uwg/socket", log.New(testWriter{t}, "", 0))
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = proxy.Serve() }()
	t.Cleanup(func() {
		_ = proxy.Close()
	})
	waitPath(t, fdSock)
	assertManagerRejects(t, fdSock, "CONNECT tcp not-an-ip 80\n")
	assertManagerRejects(t, fdSock, "CONNECT udp 100.64.94.1 999999\n")
	assertManagerRejects(t, fdSock, "LISTEN udp 100.64.94.2 999999\n")
	assertManagerRejects(t, fdSock, "ATTACH missing 123\n")
	assertManagerRejectsHugeUDPPacket(t, fdSock)

	out := runPreloadStub(t, preloadSO, fdSock, stubBin, "100.64.94.1", "18080", "preload-over-wireguard")
	if strings.TrimSpace(string(out)) != "preload-over-wireguard" {
		t.Fatalf("unexpected preload stub output %q", out)
	}

	out = runPreloadStub(t, preloadSO, fdSock, stubBin, "100.64.94.1", "18080", "preload-dup-over-wireguard", "tcp", "dup")
	if strings.TrimSpace(string(out)) != "preload-dup-over-wireguard" {
		t.Fatalf("unexpected preload dup stub output %q", out)
	}

	out = runPreloadStub(t, preloadSO, fdSock, stubBin, "100.64.94.1", "18080", "preload-fork-over-wireguard", "tcp", "fork")
	if strings.TrimSpace(string(out)) != "preload-fork-over-wireguard" {
		t.Fatalf("unexpected preload fork stub output %q", out)
	}

	out = runPreloadStub(t, preloadSO, fdSock, stubBin, "100.64.94.1", "18080", "preload-exec-over-wireguard", "tcp", "exec")
	if strings.TrimSpace(string(out)) != "preload-exec-over-wireguard" {
		t.Fatalf("unexpected preload exec stub output %q", out)
	}

	out = runPreloadStub(t, preloadSO, fdSock, stubBin, "100.64.94.1", "18081", "preload-udp-over-wireguard", "udp")
	if strings.TrimSpace(string(out)) != "preload-udp-over-wireguard" {
		t.Fatalf("unexpected preload UDP stub output %q", out)
	}

	out = runPreloadStub(t, preloadSO, fdSock, stubBin, "100.64.94.1", "18081", "preload-unconnected-udp", "udp-unconnected")
	if strings.TrimSpace(string(out)) != "preload-unconnected-udp" {
		t.Fatalf("unexpected preload unconnected UDP stub output %q", out)
	}

	out = runPreloadStubWithEnv(t, preloadSO, fdSock, stubBin, []string{"UWGS_STUB_BIND=100.64.94.2:19091"}, "100.64.94.1", "18081", "preload-bound-udp", "udp-unconnected")
	if strings.TrimSpace(string(out)) != "preload-bound-udp" {
		t.Fatalf("unexpected preload bound UDP stub output %q", out)
	}

	runPreloadTCPListener(t, preloadSO, fdSock, stubBin, serverEng, "19090")
	runPreloadTCPListener(t, preloadSO, fdSock, stubBin, serverEng, "19092", "exec")
}

func assertManagerRejects(t *testing.T, fdSock, line string) {
	t.Helper()
	c, err := net.DialTimeout("unix", fdSock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte(line)); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err == nil && strings.HasPrefix(string(buf[:n]), "OK") {
		t.Fatalf("manager accepted malicious request %q with %q", line, buf[:n])
	}
}

func assertManagerRejectsHugeUDPPacket(t *testing.T, fdSock string) {
	t.Helper()
	c, err := net.DialTimeout("unix", fdSock, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if _, err := c.Write([]byte("CONNECT udp 100.64.94.1 18081\n")); err != nil {
		t.Fatal(err)
	}
	if line, err := bufio.NewReader(c).ReadString('\n'); err != nil || !strings.HasPrefix(strings.TrimSpace(line), "OK") {
		t.Fatalf("UDP manager setup = %q, %v", line, err)
	}
	if _, err := c.Write([]byte{0xff, 0xff, 0xff, 0xff}); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if n, err := c.Read(buf); err == nil && n > 0 {
		t.Fatalf("manager returned data after huge UDP packet: %x", buf[:n])
	}
}

func runPreloadStub(t *testing.T, preloadSO, fdSock, stubBin string, args ...string) []byte {
	t.Helper()
	return runPreloadStubWithEnv(t, preloadSO, fdSock, stubBin, nil, args...)
}

func runPreloadStubWithEnv(t *testing.T, preloadSO, fdSock, stubBin string, extraEnv []string, args ...string) []byte {
	t.Helper()
	cmd := exec.Command(stubBin, args...)
	cmd.Env = append(os.Environ(), "LD_PRELOAD="+preloadSO, "UWGS_FDPROXY="+fdSock)
	cmd.Env = append(cmd.Env, extraEnv...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("preload stub %v failed: %v\n%s", args, err, out)
	}
	return out
}

func runPreloadTCPListener(t *testing.T, preloadSO, fdSock, stubBin string, serverEng *engine.Engine, port string, extra ...string) {
	t.Helper()
	args := append([]string{"100.64.94.2", port, "preload-listener", "listen-tcp"}, extra...)
	cmd := exec.Command(stubBin, args...)
	cmd.Env = append(os.Environ(), "LD_PRELOAD="+preloadSO, "UWGS_FDPROXY="+fdSock)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	reader := bufio.NewReader(stdout)
	ready, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("listener did not report readiness: %v\nstderr=%s", err, stderr.String())
	}
	if strings.TrimSpace(ready) != "READY" {
		t.Fatalf("listener readiness = %q", ready)
	}
	conn := retryTunnelDial(t, serverEng, "tcp", "100.64.94.2:"+port)
	if _, err := conn.Write([]byte("preload-listener")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("preload-listener"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if string(buf) != "preload-listener" {
		t.Fatalf("listener echo mismatch: %q", buf)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("listener stub failed: %v\nstderr=%s", err, stderr.String())
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("listener stub did not exit\nstderr=%s", stderr.String())
	}
}

func retryTunnelDial(t *testing.T, eng *engine.Engine, network, address string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		conn, err := eng.DialTunnelContext(ctx, network, address)
		cancel()
		if err == nil {
			return conn
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("dial %s %s failed: %v", network, address, last)
	return nil
}

func run(t *testing.T, dir string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}

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
	t.Cleanup(func() { _ = eng.Close() })
	return eng
}

func mustKey(t *testing.T) wgtypes.Key {
	t.Helper()
	key, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func serveEchoListener(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			_, _ = io.Copy(c, c)
		}()
	}
}

func serveUDPEcho(pc net.PacketConn) {
	buf := make([]byte, 64*1024)
	for {
		n, addr, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		_, _ = pc.WriteTo(buf[:n], addr)
	}
}

func waitPath(t *testing.T, path string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func itoa(v int) string {
	return strconv.Itoa(v)
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}
