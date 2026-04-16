// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
	"github.com/reindertpelsma/userspace-wireguard-socks/internal/engine"
)

type wrapperArtifacts struct {
	wrapper string
	preload string
	stub    string
	mixed   string
	raw     string
}

func TestUWGWrapperPtraceOnlyRawGoTCPUDP(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("ptrace wrapper test is linux/amd64 only")
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc is required for wrapper integration tests")
	}
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	out := runWrappedTarget(t, art, httpSock, "ptrace-only", art.raw, "tcp", "100.64.94.1", "18080", "ptrace-only-tcp")
	if strings.TrimSpace(string(out)) != "ptrace-only-tcp" {
		t.Fatalf("unexpected ptrace tcp output %q", out)
	}

	out = runWrappedTarget(t, art, httpSock, "ptrace-only", art.raw, "udp", "100.64.94.1", "18081", "ptrace-only-udp")
	if strings.TrimSpace(string(out)) != "ptrace-only-udp" {
		t.Fatalf("unexpected ptrace udp output %q", out)
	}

	out = runWrappedTarget(t, art, httpSock, "ptrace-only", art.raw, "stress", "100.64.94.1", "18080", "ptrace-stress", "4", "4")
	if !strings.Contains(string(out), "stress-ok") {
		t.Fatalf("expected stress-ok marker, got %q", out)
	}

	_ = serverEng
}

func TestUWGWrapperComboMixedExecForkAndCurl(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("ptrace wrapper test is linux/amd64 only")
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc is required for wrapper integration tests")
	}
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	out := runWrappedTarget(t, art, httpSock, "combo-only", art.mixed, "100.64.94.1", "18080", "combo-mixed")
	if strings.TrimSpace(string(out)) != "combo-mixed" {
		t.Fatalf("unexpected combo mixed output %q", out)
	}

	out = runWrappedTarget(t, art, httpSock, "combo-only", art.mixed, "100.64.94.1", "18080", "combo-exec", "exec")
	if strings.TrimSpace(string(out)) != "combo-exec" {
		t.Fatalf("unexpected combo exec output %q", out)
	}

	out = runWrappedTarget(t, art, httpSock, "combo-only", art.stub, "100.64.94.1", "18080", "combo-fork", "tcp", "fork")
	if strings.TrimSpace(string(out)) != "combo-fork" {
		t.Fatalf("unexpected combo fork output %q", out)
	}

	if _, err := exec.LookPath("curl"); err == nil {
		ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.94.1:18083"))
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go func() {
			_ = http.Serve(ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, "curl-over-wrapper")
			}))
		}()
		out = runWrappedTarget(t, art, httpSock, "combo-only", "curl", "-fsS", "http://100.64.94.1:18083/")
		if strings.TrimSpace(string(out)) != "curl-over-wrapper" {
			t.Fatalf("unexpected curl output %q", out)
		}
	}
}

func TestUWGWrapperPtraceOnlyTCPListener(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("ptrace wrapper test is linux/amd64 only")
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc is required for wrapper integration tests")
	}
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	cmd := wrappedCommand(t, art, httpSock, "ptrace-only", art.stub, "100.64.94.2", "19190", "ptrace-listener", "listen-tcp")
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
		t.Fatalf("listener did not become ready: %v\nstderr=%s", err, stderr.String())
	}
	if strings.TrimSpace(ready) != "READY" {
		t.Fatalf("listener readiness = %q", ready)
	}

	conn := retryTunnelDial(t, serverEng, "tcp", "100.64.94.2:19190")
	if _, err := conn.Write([]byte("ptrace-listener")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len("ptrace-listener"))
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatal(err)
	}
	_ = conn.Close()
	if string(buf) != "ptrace-listener" {
		t.Fatalf("listener echo mismatch %q", buf)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("listener wrapper failed: %v\nstderr=%s", err, stderr.String())
		}
	case <-time.After(10 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("listener wrapper did not exit\nstderr=%s", stderr.String())
	}
}

func buildWrapperArtifacts(t *testing.T) wrapperArtifacts {
	t.Helper()
	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()
	art := wrapperArtifacts{
		wrapper: filepath.Join(tmp, "uwgwrapper"),
		preload: filepath.Join(tmp, "uwgpreload.so"),
		stub:    filepath.Join(tmp, "stub_client"),
		mixed:   filepath.Join(tmp, "mixed_client"),
		raw:     filepath.Join(tmp, "raw_client"),
	}
	run(t, repo, "gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-o", art.preload, "preload/uwgpreload.c", "-ldl", "-pthread")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", art.stub, "tests/preload/testdata/stub_client.c")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", art.mixed, "tests/preload/testdata/mixed_client.c")
	buildWithEnv(t, repo, map[string]string{"CGO_ENABLED": "0"}, "go", "build", "-o", art.raw, "tests/preload/testdata/raw_client.go")
	buildWithEnv(t, repo, map[string]string{"CGO_ENABLED": "0"}, "go", "build", "-o", art.wrapper, "./cmd/uwgwrapper")
	return art
}

func setupWrapperNetwork(t *testing.T) (*engine.Engine, string) {
	t.Helper()

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

	apiSock := filepath.Join(t.TempDir(), "api.sock")
	httpSock := filepath.Join(t.TempDir(), "http.sock")
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
	t.Cleanup(func() { _ = ln.Close() })
	go serveEchoListener(ln)

	udp, err := serverEng.ListenUDP(netip.MustParseAddrPort("100.64.94.1:18081"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	go serveUDPEcho(udp)

	return serverEng, httpSock
}

func wrappedCommand(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args ...string) *exec.Cmd {
	t.Helper()
	listenSock := filepath.Join(t.TempDir(), fmt.Sprintf("fdproxy-%s.sock", strings.ReplaceAll(transport, "/", "_")))
	cmdArgs := []string{"--transport=" + transport, "--listen", listenSock, "--api", "unix:" + httpSock, "--socket-path", "/uwg/socket"}
	if os.Getenv("UWGS_TEST_DEBUG") != "" {
		cmdArgs = append([]string{"-v"}, cmdArgs...)
	}
	if os.Getenv("UWGS_TEST_DEBUG_STRESS") != "" && len(args) > 0 && args[0] == "stress" {
		cmdArgs = append([]string{"-v"}, cmdArgs...)
	}
	if transport == "combo-only" || transport == "preload-only" || transport == "prefer-hot-path" {
		cmdArgs = append(cmdArgs, "--preload", art.preload)
	}
	cmdArgs = append(cmdArgs, "--", target)
	cmdArgs = append(cmdArgs, args...)
	return exec.Command(art.wrapper, cmdArgs...)
}

func runWrappedTarget(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	base := wrappedCommand(t, art, httpSock, transport, target, args...)
	cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
	cmd.Env = append([]string{}, os.Environ()...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			t.Fatalf("wrapped target %s %v timed out\n%s", target, args, out)
		}
		t.Fatalf("wrapped target %s %v failed: %v\n%s", target, args, err, out)
	}
	return out
}

func buildWithEnv(t *testing.T, dir string, env map[string]string, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	cmd.Env = append([]string{}, os.Environ()...)
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v failed: %v\n%s", name, args, err, out)
	}
}
