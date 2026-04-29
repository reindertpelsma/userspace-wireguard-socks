//go:build linux

// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

package preload_test

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/reindertpelsma/userspace-wireguard-socks/internal/config"
)

func TestUWGWrapperEpollNonblockConnectFlow(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	for _, transport := range []string{"preload", "systrap", "systrap-supervised", "ptrace", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			out := runWrappedTargetWithOptions(t, art, httpSock, transport, art.epollNB,
				[]string{"100.64.94.1", "18080"},
				wrapperRunOptions{timeout: 90 * time.Second})
			if !bytes.Contains(out, []byte("OK epoll got")) {
				t.Fatalf("epoll nonblocking flow did not complete under %s; got:\n%s", transport, out)
			}
		})
	}
}

func TestUWGWrapperThreadedTraceeDeathDoesNotHang(t *testing.T) {
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.94.1:18082"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveHoldingListener(ln)

	for _, transport := range []string{"systrap-supervised", "systrap"} {
		t.Run(transport, func(t *testing.T) {
			out, err := runWrappedTargetAllowError(t, art, httpSock, transport, art.threadedKill,
				[]string{"100.64.94.1", "18082", "8"},
				wrapperRunOptions{timeout: 30 * time.Second})
			if err == nil {
				t.Fatalf("threaded tracee death unexpectedly exited cleanly; output:\n%s", out)
			}
			if strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
				t.Fatalf("wrapper hung after threaded tracee death; output:\n%s", out)
			}
			if !bytes.Contains(out, []byte("READY")) {
				t.Fatalf("tracee died before all worker sockets reached blocking recv; output:\n%s", out)
			}
		})
	}
}

func TestUWGWrapperThreadedTraceeDeathPtraceDiagnostic(t *testing.T) {
	if testing.Short() || strings.TrimSpace(os.Getenv("UWGS_RUN_PTRACE_THREADED_DEATH")) == "" {
		t.Skip("set UWGS_RUN_PTRACE_THREADED_DEATH=1 to run the ptrace threaded-death diagnostic")
	}
	requireWrapperToolchain(t)
	art := buildWrapperArtifacts(t)
	serverEng, httpSock := setupWrapperNetwork(t)

	ln, err := serverEng.ListenTCP(netip.MustParseAddrPort("100.64.94.1:18082"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go serveHoldingListener(ln)

	for _, transport := range []string{"ptrace", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			out, err := runWrappedTargetAllowError(t, art, httpSock, transport, art.threadedKill,
				[]string{"100.64.94.1", "18082", "8"},
				wrapperRunOptions{timeout: 30 * time.Second})
			if err == nil {
				t.Fatalf("threaded tracee death unexpectedly exited cleanly; output:\n%s", out)
			}
			if strings.Contains(err.Error(), context.DeadlineExceeded.Error()) {
				t.Fatalf("wrapper hung after threaded tracee death; output:\n%s", out)
			}
			if !bytes.Contains(out, []byte("READY")) {
				t.Fatalf("tracee died before all worker sockets reached blocking recv; output:\n%s", out)
			}
		})
	}
}

func TestUWGWrapperIPv6DirectFallbackAcrossTransports(t *testing.T) {
	requireWrapperToolchain(t)
	ln, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	defer ln.Close()
	go serveEchoListener(ln)
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	art := buildWrapperArtifacts(t)
	httpSock := setupWrapperIPv6DirectFallback(t)
	for _, transport := range []string{"preload", "systrap", "systrap-supervised", "ptrace-seccomp", "ptrace-only"} {
		t.Run(transport, func(t *testing.T) {
			out := runWrappedTargetWithOptions(t, art, httpSock, transport, art.stub,
				[]string{"::1", port, "ipv6-direct-fallback", "tcp-no-poll"},
				wrapperRunOptions{timeout: 60 * time.Second, wrapperArgs: shortListenArgs(t, transport)})
			if normalizedOutput(out) != "ipv6-direct-fallback" {
				t.Fatalf("unexpected IPv6 direct fallback output %q", out)
			}
		})
	}
}

func setupWrapperIPv6DirectFallback(t *testing.T) string {
	t.Helper()

	apiSock := t.TempDir() + "/api.sock"
	httpSock := t.TempDir() + "/http.sock"
	cfg := config.Default()
	cfg.WireGuard.PrivateKey = mustKey(t).String()
	cfg.WireGuard.Addresses = []string{"100.64.96.2/32", "fd7a:115c:a1e0::2/128"}
	cfg.API.Listen = "unix:" + apiSock
	cfg.API.AllowUnauthenticatedUnix = true
	cfg.Proxy.HTTPListeners = []string{"unix:" + httpSock}
	cfg.SocketAPI.Bind = true
	_ = mustStart(t, cfg)
	waitPath(t, httpSock)
	return httpSock
}

func serveHoldingListener(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			_, _ = io.Copy(io.Discard, c)
		}(conn)
	}
}

func runWrappedTargetAllowError(t *testing.T, art wrapperArtifacts, httpSock, transport, target string, args []string, opts wrapperRunOptions) ([]byte, error) {
	t.Helper()
	timeout := opts.timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	base := wrappedCommand(t, art, httpSock, transport, target, args, opts)
	cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
	cmd.Env = append([]string{}, base.Env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	out, err := runCommandCombinedFileBacked(t, cmd)
	if ctx.Err() == context.DeadlineExceeded {
		killProcessGroup(cmd)
		return out, ctx.Err()
	}
	killProcessGroup(cmd)
	return out, err
}
