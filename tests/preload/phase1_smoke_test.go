// Copyright (c) 2026 Reindert Pelsma
// SPDX-License-Identifier: ISC

//go:build linux

package preload_test

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// requirePhase1Toolchain is the Phase 1 equivalent of requireWrapperToolchain
// but accepts both linux/amd64 and linux/arm64. The Phase 1 SIGSYS preload
// is explicitly arch-portable (preload/core/syscall.h covers both x86_64
// and aarch64), so the test should exercise both.
func requirePhase1Toolchain(t *testing.T) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("phase1 wrapper tests are linux-only")
	}
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skipf("phase1 wrapper tests are linux/amd64 + linux/arm64 only (got %s)", runtime.GOARCH)
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skip("gcc is required for phase1 integration tests")
	}
}

// buildPhase1Artifacts builds only the artifacts the Phase 1 smoke test
// needs (the wrapper, the legacy preload as a placeholder, and the
// libc-routed C stub_client). Skips the x86_64-only rawmix/raw_client
// helpers that buildWrapperArtifacts would otherwise pull in.
func buildPhase1Artifacts(t *testing.T) wrapperArtifacts {
	t.Helper()
	repo := filepath.Clean(filepath.Join("..", ".."))
	tmp := t.TempDir()
	embeddedPreloadDir := filepath.Join(repo, "cmd", "uwgwrapper", "assets")
	embeddedPreload := filepath.Join("cmd", "uwgwrapper", "assets", "uwgpreload.so")
	art := wrapperArtifacts{
		wrapper: filepath.Join(tmp, "uwgwrapper"),
		preload: filepath.Join(tmp, "uwgpreload.so"),
		stub:    filepath.Join(tmp, "stub_client"),
	}
	if err := os.MkdirAll(embeddedPreloadDir, 0o755); err != nil {
		t.Fatalf("mkdir embedded preload dir: %v", err)
	}
	run(t, repo, "gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-o", embeddedPreload, "preload/uwgpreload.c", "-ldl", "-pthread", "-lpthread")
	run(t, repo, "gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-o", art.preload, "preload/uwgpreload.c", "-ldl", "-pthread", "-lpthread")
	run(t, repo, "gcc", "-O2", "-Wall", "-Wextra", "-o", art.stub, "tests/preload/testdata/stub_client.c")
	buildWithEnv(t, repo, map[string]string{"CGO_ENABLED": "0"}, "go", "build", "-o", art.wrapper, "./cmd/uwgwrapper")
	return art
}

// TestPhase1SeccompPreload validates the new SIGSYS+seccomp-based
// preload (preload/uwgpreload-phase1.so, built from preload/core/*)
// against a real uwgsocks engine + fdproxy.
//
// Uses the C stub_client (art.stub) rather than the Go raw_client.
// The Go runtime's signal-handling machinery (preempt signals,
// scheduler signal mask manipulation) interacts poorly with our
// SIGSYS-based interception in unexpected ways — Go-binary support
// is a known Phase 1 gap to be addressed in Phase 2 alongside the
// libc-symbol shim layer. C/libc-routed syscalls work cleanly.
//
// Subtests cover the major data-plane shapes: connected TCP, connected
// UDP, and unconnected UDP (recvfrom/sendto with sockaddr-tagged
// frames). Each must echo its sentinel message back unchanged.
func TestPhase1SeccompPreload(t *testing.T) {
	requirePhase1Toolchain(t)
	art := buildPhase1Artifacts(t)
	_, httpSock := setupWrapperNetwork(t)

	repo := filepath.Clean(filepath.Join("..", ".."))
	phase1So := filepath.Join(t.TempDir(), "uwgpreload-phase1.so")
	build := exec.Command("bash", filepath.Join("preload", "build_phase1.sh"), phase1So)
	build.Dir = repo
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build_phase1.sh failed: %v\n%s", err, out)
	}
	art.preload = phase1So

	cases := []struct {
		name   string
		modes  []string // stub_client modes to append after `host port msg`
		sentry string
		port   string
	}{
		// Connected TCP — exercises the tunnel TCP-stream fast path
		// (read/write are kernel passthrough on the manager-stream fd).
		{name: "tcp", modes: []string{"tcp"}, sentry: "phase1-tcp", port: "18080"},
		// Connected UDP — exercises uwg_write_packet / uwg_read_packet
		// for KIND_UDP_CONNECTED. read/write/recv/send all go through
		// 4-byte-length-prefix framing.
		{name: "udp_connected", modes: []string{"udp"}, sentry: "phase1-udp-conn", port: "18081"},
		// Unconnected UDP — exercises uwg_encode_udp_datagram /
		// uwg_decode_udp_datagram for KIND_UDP_LISTENER. sendto/recvfrom
		// carry the sockaddr-tagged frame (1 family + 1 padding + 2 port +
		// IP + payload).
		{name: "udp_unconnected", modes: []string{"udp-unconnected"}, sentry: "phase1-udp-unconn", port: "18081"},
		// TCP with sendmsg/recvmsg — exercises the explicit msghdr path
		// in uwg_recvmsg / uwg_sendmsg on a KIND_TCP_STREAM fd (passthrough).
		{name: "tcp_msg", modes: []string{"tcp", "msg"}, sentry: "phase1-tcp-msg", port: "18080"},
		// UDP-connected with sendmsg/recvmsg — exercises the explicit
		// msghdr path on a KIND_UDP_CONNECTED fd (framing).
		{name: "udp_msg", modes: []string{"udp", "msg"}, sentry: "phase1-udp-msg", port: "18081"},
		// UDP-connected with readv/writev — exercises the iov-scatter/
		// iov-gather paths in stream_ops.c for KIND_UDP_CONNECTED.
		{name: "udp_iov", modes: []string{"udp", "iov"}, sentry: "phase1-udp-iov", port: "18081"},
		// UDP-connected with sendmmsg/recvmmsg — exercises the multi-
		// datagram dispatch loop in msg_ops.c.
		{name: "udp_mmsg", modes: []string{"mmsg"}, sentry: "phase1-udp-mmsg", port: "18081"},
		// dup propagation — child fd from dup() must inherit proxied
		// state without re-registering with fdproxy.
		{name: "tcp_dup", modes: []string{"tcp", "dup"}, sentry: "phase1-tcp-dup", port: "18080"},
		// fork propagation — child process must keep the proxied fd
		// usable. (execve is intentionally NOT covered; Phase 1 doesn't
		// re-arm preload across exec.)
		{name: "tcp_fork", modes: []string{"tcp", "fork"}, sentry: "phase1-tcp-fork", port: "18080"},
		// UDP recv without prior poll() — exercises blocking
		// uwg_read_packet on a freshly-sent connected UDP fd.
		{name: "udp_no_poll", modes: []string{"udp-no-poll"}, sentry: "phase1-udp-np", port: "18081"},
		// Unconnected UDP recv without poll() — same but on the
		// LISTENER kind (uwg_decode_udp_datagram path).
		{name: "udp_unconnected_no_poll", modes: []string{"udp-unconnected-no-poll"}, sentry: "phase1-udp-unp", port: "18081"},
		// connect()-then-getsockname/getpeername on a UDP fd. Phase 1
		// passes these through to the kernel on the unix socketpair fd
		// (the manager-stream end after dup3). They must succeed even
		// though the underlying fd is no longer the original UDP socket
		// — the kernel returns AF_UNIX sockaddrs but the call doesn't
		// fail. Phase 1 followup: synthesize tunnel-side AF_INET sockaddrs
		// so introspection-heavy apps see a sensible answer.
		{name: "udp_connect_probe", modes: []string{"udp-connect-probe"}, sentry: "phase1-udp-probe", port: "18081"},
		// Big TCP syscall surface — exercises setsockopt/getsockopt/
		// fcntl(F_GETFL/F_SETFL/F_GETFD/F_SETFD)/getsockname/getpeername/
		// dup/dup2/dup3/poll/ppoll/read/write on a connected TCP fd.
		// Adversarial because each operation either commutes with our
		// proxied-fd state or has to passthrough cleanly; one mis-routed
		// op breaks the whole sequence.
		{name: "tcp_syscall_surface", modes: []string{"syscall-surface"}, sentry: "phase1-tcp-surface", port: "18080"},
		// Same but with the "extra" surface variant (adds shutdown,
		// extra fcntl shapes, and recv with MSG_PEEK).
		{name: "tcp_syscall_surface_extra", modes: []string{"syscall-surface-extra"}, sentry: "phase1-tcp-surface-x", port: "18080"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"100.64.94.1", tc.port, tc.sentry}, tc.modes...)
			base := wrappedCommand(t, art, httpSock, "preload", art.stub, args, wrapperRunOptions{})
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, base.Path, base.Args[1:]...)
			cmd.Env = append([]string{}, base.Env...)
			cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
			out, err := runCommandCombinedFileBacked(t, cmd)
			t.Logf("=== output (%d bytes) ===\n%s\n=== end ===", len(out), out)

			if ctx.Err() == context.DeadlineExceeded {
				t.Fatalf("timed out — see output above")
			}
			if err != nil {
				t.Fatalf("wrapper run failed: %v", err)
			}
			if !strings.Contains(string(out), tc.sentry) {
				t.Fatalf("expected %q in output; got: %q", tc.sentry, out)
			}
		})
	}
}
