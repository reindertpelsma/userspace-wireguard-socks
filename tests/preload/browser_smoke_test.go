//go:build !windows

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

type wrapperHTTPPair struct {
	serverHTTPSock string
	clientHTTPSock string
}

func TestUWGWrapperNodeHeadlessChromeSmoke(t *testing.T) {
	if os.Getenv("UWGS_RUN_HEADLESS_CHROME_SMOKE") == "" {
		t.Skip("set UWGS_RUN_HEADLESS_CHROME_SMOKE=1 to run the headless Chrome wrapper smoke")
	}
	requireWrapperToolchain(t)
	if _, err := exec.LookPath("node"); err != nil {
		t.Skip("node is required for the headless Chrome smoke test")
	}
	chromeBin := strings.TrimSpace(os.Getenv("UWGS_CHROME_BIN"))
	if chromeBin == "" {
		t.Skip("set UWGS_CHROME_BIN to a Chromium/headless_shell binary to run this smoke test")
	}

	art := buildWrapperArtifacts(t)
	pair := setupWrapperHTTPPair(t)
	transport := strings.TrimSpace(os.Getenv("UWGS_BROWSER_SMOKE_TRANSPORT"))
	if transport == "" {
		transport = "preload"
	}
	repo := filepath.Clean(filepath.Join("..", ".."))
	serverScript := filepath.Join(repo, "tests/preload/testdata/node_http_server.js")
	markFile := filepath.Join(t.TempDir(), "chrome-post.txt")

	serverCmd, serverStderr, serverDone := startWrappedListenerProcess(t, art, pair.serverHTTPSock, transport, "node",
		[]string{serverScript, "100.64.94.1", "18090", markFile},
		wrapperRunOptions{timeout: 120 * time.Second})
	defer func() {
		killProcessGroup(serverCmd)
		<-serverDone
	}()

	out, stderr := runWrappedTargetBrowser(t, art, pair.clientHTTPSock, transport, chromeBin,
		[]string{
			"--headless",
			"--no-sandbox",
			"--disable-gpu",
			"--virtual-time-budget=5000",
			"--dump-dom",
			"http://100.64.94.1:18090/",
		})
	if !strings.Contains(string(out), "script-ok:204") {
		t.Fatalf("unexpected headless chrome output %q\nbrowser stderr=%s\nserver stderr=%s", out, stderr, serverStderr.String())
	}
	waitForFileContent(t, markFile, "chrome-post-ok")
}

func setupWrapperHTTPPair(t *testing.T) wrapperHTTPPair {
	t.Helper()

	serverKey, clientKey := mustKey(t), mustKey(t)
	serverPort := freeUDPPort(t)

	serverAPISock := filepath.Join(t.TempDir(), "server-api.sock")
	serverHTTPSock := filepath.Join(t.TempDir(), "server-http.sock")
	serverCfg := config.Default()
	serverCfg.WireGuard.PrivateKey = serverKey.String()
	serverCfg.WireGuard.ListenPort = &serverPort
	serverCfg.WireGuard.Addresses = []string{"100.64.94.1/32"}
	serverCfg.API.Listen = "unix:" + serverAPISock
	serverCfg.API.AllowUnauthenticatedUnix = true
	serverCfg.Proxy.HTTPListeners = []string{"unix:" + serverHTTPSock}
	serverCfg.SocketAPI.Bind = true
	serverCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:  clientKey.PublicKey().String(),
		AllowedIPs: []string{"100.64.94.2/32"},
	}}
	_ = mustStart(t, serverCfg)

	clientAPISock := filepath.Join(t.TempDir(), "client-api.sock")
	clientHTTPSock := filepath.Join(t.TempDir(), "client-http.sock")
	clientCfg := config.Default()
	clientCfg.WireGuard.PrivateKey = clientKey.String()
	clientCfg.WireGuard.Addresses = []string{"100.64.94.2/32"}
	clientCfg.API.Listen = "unix:" + clientAPISock
	clientCfg.API.AllowUnauthenticatedUnix = true
	clientCfg.Proxy.HTTPListeners = []string{"unix:" + clientHTTPSock}
	clientCfg.SocketAPI.Bind = true
	clientCfg.WireGuard.Peers = []config.Peer{{
		PublicKey:           serverKey.PublicKey().String(),
		Endpoint:            net.JoinHostPort("127.0.0.1", itoa(serverPort)),
		AllowedIPs:          []string{"100.64.94.1/32"},
		PersistentKeepalive: 1,
	}}
	_ = mustStart(t, clientCfg)

	waitPath(t, serverHTTPSock)
	waitPath(t, clientHTTPSock)
	return wrapperHTTPPair{
		serverHTTPSock: serverHTTPSock,
		clientHTTPSock: clientHTTPSock,
	}
}

func waitForFileContent(t *testing.T, path, want string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		data, err := os.ReadFile(path)
		if err == nil {
			if string(bytes.TrimSpace(data)) == want {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	data, _ := os.ReadFile(path)
	t.Fatalf("timed out waiting for %s to contain %q, got %q", path, want, data)
}

func runWrappedTargetBrowser(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args []string) ([]byte, []byte) {
	t.Helper()

	// Chromium startup inside a stripped container (no GPU, fallback
	// software rendering, missing dbus) can take 30-50s before the
	// first network request. Add comfortable budget for the wrapped
	// browser to print --dump-dom output. 180s is well past worst
	// observed startup; still fails fast on a real hang.
	base := wrappedCommand(t, art, httpSock, transport, target, args, wrapperRunOptions{timeout: 180 * time.Second})
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
	cmd.Env = append([]string{}, base.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	stdoutPath := filepath.Join(t.TempDir(), "browser.out")
	stderrPath := filepath.Join(t.TempDir(), "browser.err")
	stdoutFile, err := os.Create(stdoutPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stdoutFile.Close()
	stderrFile, err := os.Create(stderrPath)
	if err != nil {
		t.Fatal(err)
	}
	defer stderrFile.Close()
	cmd.Stdout = stdoutFile
	cmd.Stderr = stderrFile

	runErr := cmd.Run()
	_ = stdoutFile.Close()
	_ = stderrFile.Close()
	stdout, _ := os.ReadFile(stdoutPath)
	stderr, _ := os.ReadFile(stderrPath)
	killProcessGroup(cmd)

	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("wrapped browser %s %v timed out\n%s", target, args, stderr)
	}
	if runErr != nil {
		t.Fatalf("wrapped browser %s %v failed: %v\nstdout=%s\nstderr=%s", target, args, runErr, stdout, stderr)
	}
	return stdout, stderr
}
